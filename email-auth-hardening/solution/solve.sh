#!/usr/bin/env bash
set -euo pipefail

# Rewrites the four incomplete modules so mailguard evaluates SPF with the real
# RFC 7208 check-host semantics (left-to-right short-circuit, include-returns-Pass,
# include-of-missing = PermError, the IP-dependent lookup/void budgets), expands
# macros correctly (the %{ir} reversed-IP exists check), scores and hardens DMARC in
# full, and writes every artifact at the contract paths and byte layout. The other
# modules already ship correct.

cd "${APP_DIR:-/app}"

cat > src/spf.ts <<'EOF_spf'
// SPF evaluation (RFC 7208). Two things live here. `analyzeRecord` reads a domain's
// published SPF record for its static posture (present, duplicated, the effective
// `all` disposition, whether it uses the deprecated `ptr`). `evaluateSpf` is the
// real check-host() decision procedure: it walks the record left to right against a
// specific connecting IP, short-circuiting at the first mechanism that matches,
// recursing into `include`/`redirect`, resolving `a`/`mx`/`exists` (with macro
// expansion) and enforcing the 10-lookup and 2-void limits along the evaluated
// path. An `include` contributes only when it itself evaluates to Pass.

import { parseCidr, cidrContainsIp } from './cidr.js';
import { expandMacros, type MacroContext } from './macro.js';
import type { Resolver } from './dns.js';

export type SpfOutcome = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'permerror';

const QUALIFIER_WORD: Record<string, SpfOutcome> = {
  '+': 'pass',
  '-': 'fail',
  '~': 'softfail',
  '?': 'neutral',
};

interface Term {
  modifier: boolean;
  qualifier: string;
  name: string;
  value: string;
  cidrLen: number | null;
}

function isSpfRecord(text: string): boolean {
  const low = text.trimStart().toLowerCase();
  return low === 'v=spf1' || low.startsWith('v=spf1 ');
}

function parseTerm(token: string): Term {
  const eq = token.indexOf('=');
  if (eq !== -1) {
    const key = token.slice(0, eq).toLowerCase();
    if (key === 'redirect' || key === 'exp') {
      return { modifier: true, qualifier: '+', name: key, value: token.slice(eq + 1), cidrLen: null };
    }
  }
  let qualifier = '+';
  let rest = token;
  if (rest.length > 0 && '+-~?'.includes(rest[0])) {
    qualifier = rest[0];
    rest = rest.slice(1);
  }
  let name: string;
  let value: string;
  const colon = rest.indexOf(':');
  if (colon !== -1) {
    name = rest.slice(0, colon).toLowerCase();
    value = rest.slice(colon + 1);
  } else {
    const slash = rest.indexOf('/');
    if (slash !== -1) {
      name = rest.slice(0, slash).toLowerCase();
      value = rest.slice(slash);
    } else {
      name = rest.toLowerCase();
      value = '';
    }
  }
  let cidrLen: number | null = null;
  if (name === 'a' || name === 'mx') {
    const slash = value.indexOf('/');
    if (slash !== -1) {
      const len = Number.parseInt(value.slice(slash + 1), 10);
      cidrLen = Number.isNaN(len) ? null : len;
      value = value.slice(0, slash);
    }
  }
  return { modifier: false, qualifier, name, value, cidrLen };
}

function parseTerms(record: string): Term[] {
  const parts = record.trim().split(/\s+/).filter((p) => p.length > 0);
  const terms: Term[] = [];
  for (const part of parts) {
    if (part.toLowerCase() === 'v=spf1') continue;
    terms.push(parseTerm(part));
  }
  return terms;
}

async function firstSpf(domain: string, resolver: Resolver): Promise<string | null> {
  const answer = await resolver.query(domain, 'TXT');
  const records = answer.records.filter(isSpfRecord);
  return records.length > 0 ? records[0] : null;
}

// --------------------------------------------------------------------------- #
// Static analysis (no connecting IP)
// --------------------------------------------------------------------------- #
export interface RecordAnalysis {
  present: boolean;
  multiple: boolean;
  effectiveAll: SpfOutcome;
  hasPtr: boolean;
}

async function effectiveAllOf(domain: string, resolver: Resolver, visited: Set<string>): Promise<SpfOutcome> {
  const record = await firstSpf(domain, resolver);
  if (record === null) return 'none';
  let redirect: string | null = null;
  for (const term of parseTerms(record)) {
    if (term.modifier) {
      if (term.name === 'redirect') redirect = term.value;
      continue;
    }
    if (term.name === 'all') return QUALIFIER_WORD[term.qualifier] ?? 'neutral';
  }
  if (redirect !== null && !visited.has(redirect)) {
    visited.add(redirect);
    return effectiveAllOf(redirect, resolver, visited);
  }
  return 'none';
}

export async function analyzeRecord(domain: string, resolver: Resolver): Promise<RecordAnalysis> {
  const answer = await resolver.query(domain, 'TXT');
  const records = answer.records.filter(isSpfRecord);
  if (records.length === 0) {
    return { present: false, multiple: false, effectiveAll: 'none', hasPtr: false };
  }
  const hasPtr = parseTerms(records[0]).some((t) => !t.modifier && t.name === 'ptr');
  const effectiveAll = await effectiveAllOf(domain, resolver, new Set([domain]));
  return { present: true, multiple: records.length > 1, effectiveAll, hasPtr };
}

// --------------------------------------------------------------------------- #
// check-host(): evaluate one connecting IP
// --------------------------------------------------------------------------- #
interface Ctx {
  ip: string;
  sender: string;
  lookups: number;
  voids: number;
  resolver: Resolver;
}

function chargeLookup(ctx: Ctx): boolean {
  ctx.lookups += 1;
  return ctx.lookups > 10;
}

function chargeVoid(ctx: Ctx): boolean {
  ctx.voids += 1;
  return ctx.voids > 2;
}

async function matchesA(domain: string, cidrLen: number | null, ctx: Ctx): Promise<{ match: boolean; empty: boolean }> {
  const answer = await ctx.resolver.query(domain, 'A');
  for (const addr of answer.records) {
    const cidr = parseCidr(cidrLen === null ? addr : `${addr}/${cidrLen}`);
    if (cidr !== null && cidrContainsIp(cidr, ctx.ip)) return { match: true, empty: false };
  }
  return { match: false, empty: answer.records.length === 0 };
}

async function matchesMx(domain: string, cidrLen: number | null, ctx: Ctx): Promise<{ match: boolean; empty: boolean }> {
  const answer = await ctx.resolver.query(domain, 'MX');
  if (answer.records.length === 0) return { match: false, empty: true };
  for (const host of answer.records) {
    const a = await matchesA(host, cidrLen, ctx);
    if (a.match) return { match: true, empty: false };
  }
  return { match: false, empty: false };
}

async function check(domain: string, ctx: Ctx, visited: Set<string>): Promise<SpfOutcome> {
  const record = await firstSpf(domain, ctx.resolver);
  if (record === null) return 'none';
  let redirect: string | null = null;

  for (const term of parseTerms(record)) {
    if (term.modifier) {
      if (term.name === 'redirect') redirect = term.value;
      continue;
    }
    const result = QUALIFIER_WORD[term.qualifier] ?? 'pass';
    switch (term.name) {
      case 'all':
        return result;
      case 'ip4': {
        const cidr = parseCidr(term.value);
        if (cidr !== null && cidrContainsIp(cidr, ctx.ip)) return result;
        break;
      }
      case 'ip6':
        break;
      case 'a': {
        if (chargeLookup(ctx)) return 'permerror';
        const { match, empty } = await matchesA(term.value.length > 0 ? term.value : domain, term.cidrLen, ctx);
        if (empty && chargeVoid(ctx)) return 'permerror';
        if (match) return result;
        break;
      }
      case 'mx': {
        if (chargeLookup(ctx)) return 'permerror';
        const { match, empty } = await matchesMx(term.value.length > 0 ? term.value : domain, term.cidrLen, ctx);
        if (empty && chargeVoid(ctx)) return 'permerror';
        if (match) return result;
        break;
      }
      case 'include': {
        if (chargeLookup(ctx)) return 'permerror';
        const target = term.value;
        if (visited.has(target)) return 'permerror';
        const sub = await check(target, ctx, new Set([...visited, target]));
        if (sub === 'permerror') return 'permerror';
        if (sub === 'none') return 'permerror';
        if (sub === 'pass') return result;
        break; // fail / softfail / neutral -> no match, continue
      }
      case 'exists': {
        if (chargeLookup(ctx)) return 'permerror';
        const macroCtx: MacroContext = { ip: ctx.ip, domain, sender: ctx.sender };
        const name = expandMacros(term.value, macroCtx);
        const answer = await ctx.resolver.query(name, 'A');
        if (answer.records.length === 0) {
          if (chargeVoid(ctx)) return 'permerror';
          break;
        }
        return result;
      }
      case 'ptr': {
        if (chargeLookup(ctx)) return 'permerror';
        break; // deprecated: never contributes a match in this evaluator
      }
      default:
        break;
    }
  }

  if (redirect !== null) {
    if (chargeLookup(ctx)) return 'permerror';
    if (visited.has(redirect)) return 'permerror';
    const sub = await check(redirect, ctx, new Set([...visited, redirect]));
    return sub === 'none' ? 'permerror' : sub;
  }
  return 'none';
}

export interface SpfEvaluation {
  result: SpfOutcome;
  lookups: number;
}

export async function evaluateSpf(domain: string, ip: string, resolver: Resolver): Promise<SpfEvaluation> {
  const ctx: Ctx = { ip, sender: `probe@${domain}`, lookups: 0, voids: 0, resolver };
  const result = await check(domain, ctx, new Set([domain]));
  return { result, lookups: ctx.lookups };
}

export function spfWeaknesses(analysis: RecordAnalysis, permerrorObserved: boolean, flaggedRemoved: boolean): string[] {
  if (!analysis.present) return ['spf_missing'];
  const codes = new Set<string>();
  if (analysis.multiple) codes.add('spf_multiple_records');
  if (analysis.effectiveAll === 'pass') codes.add('spf_permissive_all');
  if (analysis.effectiveAll === 'neutral') codes.add('spf_neutral_all');
  if (analysis.effectiveAll === 'softfail') codes.add('spf_softfail');
  if (analysis.effectiveAll === 'none') codes.add('spf_no_all');
  if (analysis.hasPtr) codes.add('spf_deprecated_ptr');
  if (permerrorObserved) codes.add('spf_permerror_observed');
  if (flaggedRemoved) codes.add('spf_flagged_source');
  return [...codes].sort();
}
EOF_spf

cat > src/macro.ts <<'EOF_macro'
// SPF macro expansion (RFC 7208 section 7). Macros let an `exists` mechanism build
// a query name from the connecting IP and the current domain — the classic
// `exists:%{ir}.%{d}` reversed-IP allow-list check. A macro is `%{<letter><digits?>
// <r?><delimiters?>}`; `%%`, `%_`, `%-` are literal escapes. `%{ir}` reverses the
// IP's labels; a trailing digit count keeps only that many right-most labels.

export interface MacroContext {
  ip: string; // connecting IPv4, dotted
  domain: string; // the <domain> currently being evaluated
  sender: string; // envelope sender local@domain
}

function macroValue(letter: string, ctx: MacroContext): string {
  const lower = letter.toLowerCase();
  const atSplit = ctx.sender.split('@');
  const local = atSplit.length > 1 ? atSplit[0] : 'postmaster';
  const senderDomain = atSplit.length > 1 ? atSplit[1] : ctx.domain;
  switch (lower) {
    case 's':
      return ctx.sender;
    case 'l':
      return local;
    case 'o':
      return senderDomain;
    case 'd':
      return ctx.domain;
    case 'i':
      return ctx.ip;
    case 'h':
      return ctx.domain;
    case 'v':
      return 'in-addr';
    case 'p':
      return 'unknown';
    default:
      return '';
  }
}

function applyTransformer(value: string, digits: number | null, reverse: boolean, delimiters: string): string {
  const delimSet = delimiters.length > 0 ? delimiters : '.';
  const pattern = new RegExp(`[${delimSet.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')}]`);
  let parts = value.split(pattern);
  if (reverse) parts = parts.reverse();
  if (digits !== null && digits < parts.length) parts = parts.slice(parts.length - digits);
  return parts.join('.');
}

export function expandMacros(spec: string, ctx: MacroContext): string {
  let out = '';
  let i = 0;
  while (i < spec.length) {
    const ch = spec[i];
    if (ch !== '%') {
      out += ch;
      i += 1;
      continue;
    }
    const next = spec[i + 1];
    if (next === '%') {
      out += '%';
      i += 2;
    } else if (next === '_') {
      out += ' ';
      i += 2;
    } else if (next === '-') {
      out += '%20';
      i += 2;
    } else if (next === '{') {
      const close = spec.indexOf('}', i + 2);
      if (close === -1) {
        out += ch;
        i += 1;
        continue;
      }
      const body = spec.slice(i + 2, close);
      const letter = body[0];
      let rest = body.slice(1);
      let digits: number | null = null;
      const digitMatch = rest.match(/^\d+/);
      if (digitMatch) {
        digits = Number.parseInt(digitMatch[0], 10);
        rest = rest.slice(digitMatch[0].length);
      }
      let reverse = false;
      if (rest.startsWith('r') || rest.startsWith('R')) {
        reverse = true;
        rest = rest.slice(1);
      }
      const delimiters = rest;
      out += applyTransformer(macroValue(letter, ctx), digits, reverse, delimiters);
      i = close + 1;
    } else {
      out += ch;
      i += 1;
    }
  }
  return out;
}
EOF_macro

cat > src/dmarc.ts <<'EOF_dmarc'
// DMARC record parsing, weakness detection and hardening. A domain's DMARC policy
// lives in the TXT record at `_dmarc.<domain>`; this module reads the tags that
// matter for anti-spoofing posture (the policy `p`, the subdomain policy `sp`, the
// sampling `pct`, the DKIM/SPF alignment modes and whether aggregate reporting is
// configured) and synthesises the hardened replacement record.

import type { Resolver } from './dns.js';
import type { HardenConfig } from './model.js';

export interface DmarcResult {
  present: boolean;
  policy: string;
  subdomainPolicy: string;
  spExplicit: boolean;
  pct: number;
  adkim: string;
  aspf: string;
  hasRua: boolean;
}

function isDmarcRecord(text: string): boolean {
  return text.trimStart().toLowerCase().startsWith('v=dmarc1');
}

function parseTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const segment of record.split(';')) {
    const trimmed = segment.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    if (key.length > 0 && key !== 'v' && !tags.has(key)) tags.set(key, value);
  }
  return tags;
}

function normPolicy(value: string | undefined): string {
  const low = (value ?? '').toLowerCase();
  return low === 'reject' || low === 'quarantine' ? low : 'none';
}

function normAlign(value: string | undefined): string {
  return (value ?? '').toLowerCase() === 's' ? 's' : 'r';
}

export function parseDmarc(record: string): DmarcResult {
  const tags = parseTags(record);
  const policy = normPolicy(tags.get('p'));
  const spExplicit = tags.has('sp');
  const subdomainPolicy = spExplicit ? normPolicy(tags.get('sp')) : policy;
  const pctRaw = Number.parseInt(tags.get('pct') ?? '', 10);
  const pct = Number.isNaN(pctRaw) ? 100 : pctRaw;
  return {
    present: true,
    policy,
    subdomainPolicy,
    spExplicit,
    pct,
    adkim: normAlign(tags.get('adkim')),
    aspf: normAlign(tags.get('aspf')),
    hasRua: tags.has('rua') && (tags.get('rua') ?? '').length > 0,
  };
}

export async function resolveDmarc(domain: string, resolver: Resolver): Promise<DmarcResult> {
  const answer = await resolver.query(`_dmarc.${domain}`, 'TXT');
  const records = answer.records.filter(isDmarcRecord);
  if (records.length === 0) {
    return { present: false, policy: 'none', subdomainPolicy: 'none', spExplicit: false, pct: 100, adkim: 'r', aspf: 'r', hasRua: false };
  }
  return parseDmarc(records[0]);
}

export function dmarcWeaknesses(result: DmarcResult): string[] {
  if (!result.present) return ['dmarc_missing'];
  const codes = new Set<string>();
  if (result.policy === 'none') codes.add('dmarc_policy_none');
  if (result.policy === 'quarantine') codes.add('dmarc_policy_quarantine');
  if (result.spExplicit && result.subdomainPolicy !== 'reject') codes.add('dmarc_subdomain_gap');
  if (result.pct < 100) codes.add('dmarc_partial_pct');
  if (result.adkim === 'r' || result.aspf === 'r') codes.add('dmarc_relaxed_alignment');
  if (!result.hasRua) codes.add('dmarc_rua_missing');
  return [...codes].sort();
}

export function hardenDmarc(config: HardenConfig): string {
  const p = config.policy;
  return `v=DMARC1; p=${p}; sp=${p}; adkim=s; aspf=s; pct=100; rua=${config.rua}`;
}
EOF_dmarc

cat > src/report.ts <<'EOF_report'
// Rendering: the canonical JSON report (per-observation SPF verdicts plus a
// per-domain assessment), the hardened SPF and DMARC zone files, and the Markdown
// audit note. This module owns the paths and the byte layout of every artifact.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalJson, compareCodePoints } from './canonical.js';

export interface Observation {
  id: string;
  domain: string;
  ip: string;
  spfResult: string;
  lookups: number;
}

export interface SpfAssessment {
  present: boolean;
  effectiveAll: string;
  passCount: number;
  permerrorCount: number;
  weaknesses: string[];
  record: string;
}

export interface DmarcAssessment {
  present: boolean;
  policy: string;
  subdomainPolicy: string;
  pct: number;
  adkim: string;
  aspf: string;
  weaknesses: string[];
  record: string;
}

export interface DomainAssessment {
  domain: string;
  spf: SpfAssessment;
  dmarc: DmarcAssessment;
}

export interface Report {
  observations: Observation[];
  domains: DomainAssessment[];
  removedTotal: number;
}

function writeFile(outDir: string, rel: string, contents: string): void {
  const full = join(outDir, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents);
}

function reportObject(observations: Observation[], domains: DomainAssessment[], removedTotal: number): unknown {
  const spfPass = observations.filter((o) => o.spfResult === 'pass').length;
  const spfPerm = observations.filter((o) => o.spfResult === 'permerror').length;
  const dmarcWeak = domains.filter((d) => d.dmarc.weaknesses.length > 0).length;
  return {
    generated_by: 'mailguard',
    report_version: '1',
    observations: observations.map((o) => ({
      id: o.id,
      domain: o.domain,
      ip: o.ip,
      spf_result: o.spfResult,
      lookups: o.lookups,
    })),
    domains: domains.map((d) => ({
      domain: d.domain,
      spf: {
        present: d.spf.present,
        effective_all: d.spf.effectiveAll,
        pass_count: d.spf.passCount,
        permerror_count: d.spf.permerrorCount,
        weaknesses: d.spf.weaknesses,
        hardened_record: d.spf.record,
      },
      dmarc: {
        present: d.dmarc.present,
        policy: d.dmarc.policy,
        subdomain_policy: d.dmarc.subdomainPolicy,
        pct: d.dmarc.pct,
        adkim: d.dmarc.adkim,
        aspf: d.dmarc.aspf,
        weaknesses: d.dmarc.weaknesses,
        hardened_record: d.dmarc.record,
      },
    })),
    summary: {
      observations: observations.length,
      domains: domains.length,
      spf_pass: spfPass,
      spf_permerror: spfPerm,
      dmarc_weak: dmarcWeak,
      flagged_sources_removed: removedTotal,
    },
  };
}

function auditLines(observations: Observation[], domains: DomainAssessment[], removedTotal: number): string {
  const lines = [
    '# Email authentication hardening audit',
    '',
    `Domains assessed: ${domains.length}`,
    `Observations evaluated: ${observations.length}`,
    `SPF records with weaknesses: ${domains.filter((d) => d.spf.weaknesses.length > 0).length}`,
    `DMARC records with weaknesses: ${domains.filter((d) => d.dmarc.weaknesses.length > 0).length}`,
    `Flagged sources removed: ${removedTotal}`,
    '',
  ];
  for (const d of domains) {
    const spfWeak = d.spf.weaknesses.length > 0 ? d.spf.weaknesses.join(', ') : 'none';
    const dmarcWeak = d.dmarc.weaknesses.length > 0 ? d.dmarc.weaknesses.join(', ') : 'none';
    lines.push(`## ${d.domain}`);
    lines.push('');
    lines.push(`SPF: effective all ${d.spf.effectiveAll}, pass ${d.spf.passCount}, permerror ${d.spf.permerrorCount}, weaknesses ${spfWeak}`);
    lines.push(`DMARC: policy ${d.dmarc.policy}, weaknesses ${dmarcWeak}`);
    lines.push('');
  }
  return lines.join('\n');
}

export function writeArtifacts(outDir: string, report: Report): void {
  const observations = [...report.observations].sort((a, b) => compareCodePoints(a.id, b.id));
  const domains = [...report.domains].sort((a, b) => compareCodePoints(a.domain, b.domain));

  writeFile(outDir, 'email-auth-report.json', canonicalJson(reportObject(observations, domains, report.removedTotal)));

  for (const d of domains) {
    writeFile(outDir, `zones/${d.domain}/spf.txt`, `${d.spf.record}\n`);
    writeFile(outDir, `zones/${d.domain}/dmarc.txt`, `${d.dmarc.record}\n`);
  }

  writeFile(outDir, 'email-auth-audit.md', auditLines(observations, domains, report.removedTotal));
}
EOF_report

# Recompile so /app/dist reflects the repaired sources.
npm run build

# Demonstrate the repaired tool end to end: start the bundled mock DNS resolver and
# spoof-intel feed, run /app/bin/mailguard against the shipped /app/data fixtures, and
# confirm it writes the JSON report, the per-domain zone files and the Markdown audit.
chmod +x bin/mailguard

node tools/dns-server.mjs &
dns_pid=$!
node tools/feed-server.mjs &
feed_pid=$!
trap 'kill "$dns_pid" "$feed_pid" 2>/dev/null || true' EXIT

wait_port() {
  for _ in $(seq 1 100); do
    if node -e "require('net').connect($1, '127.0.0.1').on('connect', () => process.exit(0)).on('error', () => process.exit(1))"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}
wait_port 8785
wait_port 8786

rm -rf out
/app/bin/mailguard

test -f out/email-auth-report.json
test -f out/email-auth-audit.md
ls out/zones/*/spf.txt >/dev/null
ls out/zones/*/dmarc.txt >/dev/null
echo "mailguard produced $(find out -type f | wc -l) artifacts under $(pwd)/out:"
find out -type f | sort

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
        return result;
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

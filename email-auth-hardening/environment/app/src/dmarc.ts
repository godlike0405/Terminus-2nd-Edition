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
  if (!result.hasRua) codes.add('dmarc_rua_missing');
  return [...codes].sort();
}

export function hardenDmarc(config: HardenConfig): string {
  return `v=DMARC1; p=${config.policy}; rua=${config.rua}`;
}

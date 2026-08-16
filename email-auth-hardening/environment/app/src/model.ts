// Estate model: the managed domains in scope and the hardening configuration
// (the aggregate-report address, the target DMARC policy and the target SPF `all`
// qualifier). The loaders read the shipped JSON fixtures.

import { readFileSync } from 'node:fs';

export interface Scope {
  domains: string[];
}

export interface Probe {
  id: string;
  domain: string;
  ip: string;
}

export interface HardenConfig {
  rua: string;
  policy: string;
  spfAll: string;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function loadScope(path: string): Scope {
  const raw = readJson(path) as { domains?: string[] };
  return { domains: raw.domains ?? [] };
}

export function loadProbes(path: string): Probe[] {
  const raw = readJson(path) as { probes?: Probe[] };
  return raw.probes ?? [];
}

export function loadHardenConfig(path: string): HardenConfig {
  const raw = readJson(path) as { rua?: string; policy?: string; spf_all?: string };
  return {
    rua: raw.rua && raw.rua.length > 0 ? raw.rua : 'mailto:dmarc-reports@localhost',
    policy: raw.policy === 'quarantine' ? 'quarantine' : 'reject',
    spfAll: raw.spf_all && raw.spf_all.length > 0 ? raw.spf_all : '-all',
  };
}

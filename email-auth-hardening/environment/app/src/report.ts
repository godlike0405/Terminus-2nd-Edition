// Rendering: the canonical JSON report (per-observation SPF verdicts plus a
// per-domain assessment), the hardened SPF and DMARC zone files, and the Markdown
// audit note. This module owns the paths and the byte layout of every artifact.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { compareCodePoints } from './canonical.js';

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
    report_version: 1,
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

  writeFile(outDir, 'email-auth-report.json', JSON.stringify(reportObject(observations, domains, report.removedTotal), null, 2));

  for (const d of domains) {
    writeFile(outDir, `zones/${d.domain}.spf`, `${d.spf.record}\n`);
    writeFile(outDir, `zones/${d.domain}.dmarc`, `${d.dmarc.record}\n`);
  }

  writeFile(outDir, 'audit.md', auditLines(observations, domains, report.removedTotal));
}

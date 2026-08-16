// mailguard entry point: load the in-scope domains, the observed connecting IPs
// and the hardening config; for every observation evaluate the connecting IP
// against its domain's published SPF record (the full check-host walk); analyse and
// score each domain's SPF and DMARC posture; harden the SPF record to exactly the
// IPs that legitimately pass today minus the flagged sources; and write the report,
// hardened records and audit.

import { loadConfig } from './config.js';
import { loadHardenConfig, loadProbes, loadScope, type Probe } from './model.js';
import { httpResolver } from './dns.js';
import { queryFeed } from './feed.js';
import { analyzeRecord, evaluateSpf, spfWeaknesses } from './spf.js';
import { resolveDmarc, dmarcWeaknesses, hardenDmarc } from './dmarc.js';
import { hardenSpf } from './harden.js';
import { writeArtifacts, type DomainAssessment, type Observation, type Report } from './report.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const scope = loadScope(config.scopePath);
  const probes = loadProbes(config.probesPath);
  const hardenConfig = loadHardenConfig(config.configPath);
  const resolver = httpResolver(config.dnsBase);
  const flagged = await queryFeed(config.feedBase);

  const byDomain = new Map<string, Probe[]>();
  for (const probe of probes) {
    if (!byDomain.has(probe.domain)) byDomain.set(probe.domain, []);
    byDomain.get(probe.domain)!.push(probe);
  }

  const observations: Observation[] = [];
  const domains: DomainAssessment[] = [];
  let removedTotal = 0;

  for (const domain of scope.domains) {
    const analysis = await analyzeRecord(domain, resolver);
    const domainProbes = byDomain.get(domain) ?? [];

    const passingIps: string[] = [];
    let permerrorCount = 0;
    let passCount = 0;
    for (const probe of domainProbes) {
      const evaluation = await evaluateSpf(domain, probe.ip, resolver);
      observations.push({ id: probe.id, domain, ip: probe.ip, spfResult: evaluation.result, lookups: evaluation.lookups });
      if (evaluation.result === 'pass') {
        passingIps.push(probe.ip);
        passCount += 1;
      } else if (evaluation.result === 'permerror') {
        permerrorCount += 1;
      }
    }

    const hardened = hardenSpf(passingIps, flagged, hardenConfig);
    removedTotal += hardened.removed.length;
    const spfWeak = spfWeaknesses(analysis, permerrorCount > 0, hardened.removed.length > 0);

    const dmarc = await resolveDmarc(domain, resolver);
    const dmarcWeak = dmarcWeaknesses(dmarc);

    domains.push({
      domain,
      spf: {
        present: analysis.present,
        effectiveAll: analysis.effectiveAll,
        passCount,
        permerrorCount,
        weaknesses: spfWeak,
        record: hardened.record,
      },
      dmarc: {
        present: dmarc.present,
        policy: dmarc.policy,
        subdomainPolicy: dmarc.subdomainPolicy,
        pct: dmarc.pct,
        adkim: dmarc.adkim,
        aspf: dmarc.aspf,
        weaknesses: dmarcWeak,
        record: hardenDmarc(hardenConfig),
      },
    });
  }

  const report: Report = { observations, domains, removedTotal };
  writeArtifacts(config.outDir, report);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

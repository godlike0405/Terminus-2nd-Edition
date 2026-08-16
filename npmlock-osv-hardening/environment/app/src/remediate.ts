// Remediation policy.
//
// For each in-scope package resolved to name@version:
//   - no applicable advisory                    -> ok      (clean)
//   - otherwise choose the LOWEST registry version that is above the installed
//     version, is affected by none of the package's advisories, and satisfies
//     every requirement range declared for the package. That is the upgrade
//     target                                    -> upgrade (vulnerable_fixable)
//   - if a higher unaffected version exists but none satisfies every requirement
//     range                                     -> block   (no_safe_version)
//   - if no higher version clears every advisory -> block  (no_fix)

import { advisoryHit, type OsvVuln } from './osv.js';
import { compareVersions, satisfies } from './semver.js';
import type { InstalledPackage } from './lockfile.js';

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export type Decision = 'upgrade' | 'block' | 'ok';

export interface Finding {
  name: string;
  installed_version: string;
  paths: string[];
  constraints: string[];
  decision: Decision;
  reason: string;
  target_version: string | null;
  max_severity: string | null;
  advisories: string[];
}

function unaffectedByAll(advisories: OsvVuln[], name: string, version: string): boolean {
  return !advisories.some((vuln) => advisoryHit(vuln, name, version).hit);
}

export function decidePackage(pkg: InstalledPackage, advisories: OsvVuln[], registry: string[]): Finding {
  const base = {
    name: pkg.name,
    installed_version: pkg.version,
    paths: pkg.paths,
    constraints: pkg.constraints,
  };

  const applicable: OsvVuln[] = [];
  for (const vuln of advisories) {
    if (advisoryHit(vuln, pkg.name, pkg.version).hit) applicable.push(vuln);
  }

  if (applicable.length === 0) {
    return { ...base, decision: 'ok', reason: 'clean', target_version: null, max_severity: null, advisories: [] };
  }

  const ids = applicable.map((vuln) => vuln.id).sort();
  let severity = 'LOW';
  for (const vuln of applicable) {
    const value = vuln.database_specific?.severity ?? 'LOW';
    if (SEVERITIES.indexOf(value) > SEVERITIES.indexOf(severity)) severity = value;
  }

  const higherUnaffected = registry.filter(
    (candidate) => compareVersions(candidate, pkg.version) > 0 && unaffectedByAll(advisories, pkg.name, candidate),
  );
  const satisfying = higherUnaffected.filter((candidate) =>
    pkg.constraints.every((range) => satisfies(candidate, range)),
  );

  if (satisfying.length > 0) {
    let target = satisfying[0];
    for (const candidate of satisfying) {
      if (compareVersions(candidate, target) < 0) target = candidate;
    }
    return {
      ...base,
      decision: 'upgrade',
      reason: 'vulnerable_fixable',
      target_version: target,
      max_severity: severity,
      advisories: ids,
    };
  }

  const reason = higherUnaffected.length > 0 ? 'no_safe_version' : 'no_fix';
  return { ...base, decision: 'block', reason, target_version: null, max_severity: severity, advisories: ids };
}

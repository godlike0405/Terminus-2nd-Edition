// Hardening decision policy.
//
// For each in-scope service resolved to package@version:
//   - unresolved version                       -> block (unverifiable)
//   - no applicable advisory                   -> ok    (clean)
//   - an applicable advisory with no fix        -> block (no_fix)
//   - otherwise pin to the highest fixed version that clears every applicable
//     advisory, unless that target is itself still affected by some advisory,
//     in which case                            -> block (no_safe_version)

import { advisoryHit, type OsvVuln } from './osv.js';
import { compareDeb } from './debver.js';
import type { ServiceRecord } from './inventory.js';

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export type Decision = 'pin' | 'block' | 'ok';

export interface ServiceDecision {
  unit: string;
  enabled: boolean;
  exec_path: string;
  package: string | null;
  installed_version: string | null;
  decision: Decision;
  reason: string;
  pin_version: string | null;
  max_severity: string | null;
  advisories: string[];
}

export function decideService(service: ServiceRecord, advisories: OsvVuln[]): ServiceDecision {
  const base = {
    unit: service.unit,
    enabled: service.enabled,
    exec_path: service.exec_path,
    package: service.package,
    installed_version: service.version,
  };

  if (service.version === null || service.package === null) {
    return { ...base, decision: 'block', reason: 'unverifiable', pin_version: null, max_severity: null, advisories: [] };
  }

  const applicable: { vuln: OsvVuln; fixed: string | null }[] = [];
  for (const vuln of advisories) {
    const result = advisoryHit(vuln, service.package, service.version);
    if (result.hit) applicable.push({ vuln, fixed: result.fixed });
  }

  if (applicable.length === 0) {
    return { ...base, decision: 'ok', reason: 'clean', pin_version: null, max_severity: null, advisories: [] };
  }

  const ids = applicable.map((entry) => entry.vuln.id).sort();
  let severity = 'LOW';
  for (const entry of applicable) {
    const value = entry.vuln.database_specific?.severity ?? 'LOW';
    if (SEVERITIES.indexOf(value) > SEVERITIES.indexOf(severity)) severity = value;
  }

  if (applicable.some((entry) => entry.fixed === null)) {
    return { ...base, decision: 'block', reason: 'no_fix', pin_version: null, max_severity: severity, advisories: ids };
  }

  let target: string | null = null;
  for (const entry of applicable) {
    if (target === null || compareDeb(entry.fixed as string, target) > 0) target = entry.fixed;
  }
  const stillAffected = advisories.some((vuln) => advisoryHit(vuln, service.package as string, target as string).hit);
  if (stillAffected) {
    return { ...base, decision: 'block', reason: 'no_safe_version', pin_version: null, max_severity: severity, advisories: ids };
  }
  return { ...base, decision: 'pin', reason: 'vulnerable_fixable', pin_version: target, max_severity: severity, advisories: ids };
}

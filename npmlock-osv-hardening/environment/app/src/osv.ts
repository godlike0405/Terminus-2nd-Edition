// OSV advisory client and version-range containment for the npm ecosystem.
//
// The migration to the hosted advisory API is unfinished: the fetch path is not
// wired up yet, and containment still uses the placeholder check from the
// prototype that only looked at the first boundary of a range.

import { compareVersions } from './semver.js';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
}

export interface OsvVuln {
  id: string;
  withdrawn?: string;
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
}

// Whether an advisory applies to package@version, and the fixed version of the
// containing interval when one exists.
export function advisoryHit(
  vuln: OsvVuln,
  packageName: string,
  version: string,
): { hit: boolean; fixed: string | null } {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      const events = range.events ?? [];
      const introduced = events.find((event) => event.introduced !== undefined)?.introduced;
      if (introduced !== undefined && compareVersions(version, introduced) >= 0) {
        return { hit: true, fixed: null };
      }
    }
  }
  return { hit: false, fixed: null };
}

export async function queryOsv(_base: string, _packageName: string): Promise<OsvVuln[]> {
  // TODO: call the advisory API and return the parsed vulns.
  return [];
}

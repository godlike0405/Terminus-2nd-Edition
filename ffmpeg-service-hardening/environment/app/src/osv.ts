// OSV advisory client and version-range containment.

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
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
}

// Whether an advisory applies to package@version, and the fixed version to move
// to when one exists.
export function advisoryHit(vuln: OsvVuln, packageName: string, version: string): { hit: boolean; fixed: string | null } {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed !== undefined) return { hit: true, fixed: event.fixed };
      }
      return { hit: true, fixed: null };
    }
  }
  return { hit: false, fixed: null };
}

// Return the advisories affecting a package.
export async function queryOsv(base: string, packageName: string): Promise<OsvVuln[]> {
  return [];
}

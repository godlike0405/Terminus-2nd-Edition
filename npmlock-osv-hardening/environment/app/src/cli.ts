// npmguard entry point: read the lockfile and registry snapshot, query OSV for
// each distinct in-scope package, decide each package, and write the remediation
// artifacts and audit note.

import { loadConfig } from './config.js';
import { loadLockfile } from './lockfile.js';
import { loadRegistry, versionsOf } from './registry.js';
import { queryOsv, type OsvVuln } from './osv.js';
import { decidePackage, type Finding } from './remediate.js';
import { writeArtifacts } from './report.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const packages = loadLockfile(config.lockfilePath).filter((pkg) => pkg.production);
  const registry = loadRegistry(config.registryPath);

  const advisories = new Map<string, OsvVuln[]>();
  for (const pkg of packages) {
    if (!advisories.has(pkg.name)) advisories.set(pkg.name, await queryOsv(config.osvBase, pkg.name));
  }

  const findings: Finding[] = packages.map((pkg) =>
    decidePackage(pkg, advisories.get(pkg.name) ?? [], versionsOf(registry, pkg.name)),
  );

  writeArtifacts(config.outDir, findings);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

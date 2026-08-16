// ffguard entry point: read the host-state inventory, query OSV for each
// distinct FFmpeg package, decide each service, and write the configuration
// artifacts and audit note.

import { loadConfig } from './config.js';
import { loadInventory } from './inventory.js';
import { queryOsv, type OsvVuln } from './osv.js';
import { decideService, type ServiceDecision } from './policy.js';
import { writeArtifacts } from './report.js';

async function main(): Promise<void> {
  const config = loadConfig();
  const services = await loadInventory(config.dbPath);

  const packages = [...new Set(services.filter((s) => s.version !== null).map((s) => s.package as string))];
  const advisories = new Map<string, OsvVuln[]>();
  for (const name of packages) {
    advisories.set(name, await queryOsv(config.osvBase, name));
  }

  const decisions: ServiceDecision[] = services.map((service) =>
    decideService(service, service.package !== null ? advisories.get(service.package) ?? [] : []),
  );

  writeArtifacts(config.outDir, decisions);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

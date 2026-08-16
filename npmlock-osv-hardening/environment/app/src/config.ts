// Runtime configuration. The lockfile, the registry snapshot, the OSV API base
// URL, and the output directory are all overridable so the same tool serves the
// shipped fixtures and any other project snapshot.

export interface Config {
  lockfilePath: string;
  registryPath: string;
  osvBase: string;
  outDir: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    lockfilePath:
      env.LOCKFILE_PATH && env.LOCKFILE_PATH.length > 0 ? env.LOCKFILE_PATH : '/app/data/package-lock.json',
    registryPath:
      env.REGISTRY_PATH && env.REGISTRY_PATH.length > 0 ? env.REGISTRY_PATH : '/app/data/registry.json',
    osvBase: env.OSV_API_BASE && env.OSV_API_BASE.length > 0 ? env.OSV_API_BASE : 'http://127.0.0.1:8730',
    outDir: env.OUTPUT_DIR && env.OUTPUT_DIR.length > 0 ? env.OUTPUT_DIR : '/app/out',
  };
}

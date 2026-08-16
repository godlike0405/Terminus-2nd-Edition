// Runtime configuration. The host-state database, the OSV API base URL, and the
// output directory are all overridable so the same tool serves the shipped
// fixtures and any other host snapshot.

export interface Config {
  dbPath: string;
  osvBase: string;
  outDir: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    dbPath: env.HOST_STATE_DB && env.HOST_STATE_DB.length > 0 ? env.HOST_STATE_DB : '/app/data/host_state.db',
    osvBase: env.OSV_API_BASE && env.OSV_API_BASE.length > 0 ? env.OSV_API_BASE : 'http://127.0.0.1:8730',
    outDir: env.OUTPUT_DIR && env.OUTPUT_DIR.length > 0 ? env.OUTPUT_DIR : '/app/out',
  };
}

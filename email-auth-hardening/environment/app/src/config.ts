// Runtime configuration. The scope file, the mock DNS resolver base URL, the
// spoof-intel feed base URL and the output directory are overridable so the same
// tool serves the shipped fixtures and any other estate snapshot.

export interface Config {
  scopePath: string;
  probesPath: string;
  configPath: string;
  dnsBase: string;
  feedBase: string;
  outDir: string;
}

function pick(value: string | undefined, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    scopePath: pick(env.SCOPE_PATH, '/app/data/scope.json'),
    probesPath: pick(env.PROBES_PATH, '/app/data/probes.json'),
    configPath: pick(env.POLICY_PATH, '/app/data/config.json'),
    dnsBase: pick(env.DNS_API_BASE, 'http://127.0.0.1:8785'),
    feedBase: pick(env.FEED_API_BASE, 'http://127.0.0.1:8786'),
    outDir: pick(env.OUTPUT_DIR, '/app/out'),
  };
}

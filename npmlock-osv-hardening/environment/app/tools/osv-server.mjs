#!/usr/bin/env node
// Local OSV advisory mirror. Serves the same POST /v1/query contract as the
// public OSV API from the JSON files under vendor/osv, so the tool can be
// exercised offline against the shipped project snapshot.
//
// Usage: node /app/tools/osv-server.mjs [port] [advisories-dir]
//   port default 8730, advisories-dir default /app/vendor/osv
//
// A package name is scoped (`@scope/name`); the `/` becomes `__` in the file
// name so it stays a single path segment.
import { createServer } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const port = Number(process.argv[2] ?? process.env.OSV_PORT ?? 8730);
const dir = process.argv[3] ?? '/app/vendor/osv';

const server = createServer((request, response) => {
  if (request.method !== 'POST' || !request.url || !request.url.startsWith('/v1/query')) {
    response.writeHead(404).end();
    return;
  }
  const chunks = [];
  request.on('data', (chunk) => chunks.push(chunk));
  request.on('end', () => {
    let name;
    try {
      name = JSON.parse(Buffer.concat(chunks).toString('utf8')).package.name;
    } catch {
      response.writeHead(400).end();
      return;
    }
    const file = join(dir, `${String(name).split('/').join('__')}.json`);
    const vulns = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')).vulns ?? [] : [];
    const body = JSON.stringify({ vulns });
    response.writeHead(200, { 'Content-Type': 'application/json' }).end(body);
  });
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`osv mirror listening on http://127.0.0.1:${port}\n`);
});

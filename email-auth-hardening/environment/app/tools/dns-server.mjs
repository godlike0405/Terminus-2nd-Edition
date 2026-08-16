// Local mirror of the DNS resolver, backed by /app/data/zones.json (a map of
// name -> { TXT: [...], A: [...], MX: [...] }). Start it with
// `node tools/dns-server.mjs` to serve the same GET /resolve contract mailguard
// queries at runtime.
//
//   GET /resolve?name=<name>&type=<TXT|A|MX>
//   -> { "name": "...", "type": "TXT", "status": "NOERROR"|"NXDOMAIN", "records": [...] }

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

const port = Number.parseInt(process.env.DNS_PORT ?? '8785', 10);
const dbPath = process.env.ZONES_DB ?? '/app/data/zones.json';
const db = JSON.parse(readFileSync(dbPath, 'utf8'));

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method !== 'GET' || url.pathname !== '/resolve') {
    res.writeHead(404).end();
    return;
  }
  const name = url.searchParams.get('name') ?? '';
  const type = url.searchParams.get('type') ?? 'TXT';
  const zone = Object.prototype.hasOwnProperty.call(db, name) ? db[name] : null;
  const status = zone === null ? 'NXDOMAIN' : 'NOERROR';
  const records = zone && Array.isArray(zone[type]) ? zone[type] : [];
  const payload = JSON.stringify({ name, type, status, records });
  res.writeHead(200, { 'content-type': 'application/json' }).end(payload);
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`dns resolver on http://127.0.0.1:${port}\n`);
});

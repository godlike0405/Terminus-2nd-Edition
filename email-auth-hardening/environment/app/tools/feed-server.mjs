// Local mirror of the spoof-intel feed, backed by /app/data/feed.json. Start it
// with `node tools/feed-server.mjs` to serve the same GET /v1/flagged contract
// mailguard queries at runtime.
//
//   GET /v1/flagged
//   -> { "sources": [ { "cidr": "203.0.113.0/24", "reason": "..." }, ... ] }

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

const port = Number.parseInt(process.env.FEED_PORT ?? '8786', 10);
const dbPath = process.env.FEED_DB ?? '/app/data/feed.json';
const db = JSON.parse(readFileSync(dbPath, 'utf8'));

const server = createServer((req, res) => {
  if (req.method !== 'GET' || req.url !== '/v1/flagged') {
    res.writeHead(404).end();
    return;
  }
  const payload = JSON.stringify({ sources: db.sources ?? [] });
  res.writeHead(200, { 'content-type': 'application/json' }).end(payload);
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`spoof-intel feed on http://127.0.0.1:${port}\n`);
});

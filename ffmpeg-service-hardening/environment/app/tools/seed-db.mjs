#!/usr/bin/env node
// Build the host-state SQLite inventory from its SQL definition.
// Usage: node /app/tools/seed-db.mjs [sql-file] [db-file]
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import initSqlJs from 'sql.js';

const sqlPath = process.argv[2] ?? '/app/data/host_state.sql';
const dbPath = process.argv[3] ?? '/app/data/host_state.db';

if (existsSync(dbPath)) rmSync(dbPath);

const SQL = await initSqlJs();
const db = new SQL.Database();
db.run(readFileSync(sqlPath, 'utf8'));
writeFileSync(dbPath, Buffer.from(db.export()));
db.close();
process.stdout.write(`seeded ${dbPath}\n`);

// Host-state inventory access.
//
// The inventory is a SQLite database with packages(name, version, ecosystem),
// binaries(path, package) and services(unit, exec_path, enabled). An FFmpeg
// service is a unit whose executable basename is one of the FFmpeg tools.

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import initSqlJs, { type Database } from 'sql.js';

export const FFMPEG_TOOLS = new Set(['ffmpeg', 'ffprobe']);

export interface ServiceRecord {
  unit: string;
  exec_path: string;
  enabled: boolean;
  package: string | null;
  version: string | null;
}

function rows(db: Database, sql: string, params: (string | number)[] = []): Record<string, unknown>[] {
  const statement = db.prepare(sql);
  statement.bind(params);
  const out: Record<string, unknown>[] = [];
  while (statement.step()) out.push(statement.getAsObject());
  statement.free();
  return out;
}

export async function loadInventory(dbPath: string): Promise<ServiceRecord[]> {
  const SQL = await initSqlJs();
  const db = new SQL.Database(readFileSync(dbPath));
  try {
    const services = rows(db, 'SELECT unit, exec_path, enabled FROM services ORDER BY unit').filter(
      (service) => FFMPEG_TOOLS.has(basename(String(service.exec_path))),
    );
    const records: ServiceRecord[] = [];
    for (const service of services) {
      const execPath = String(service.exec_path);
      // Resolve the installed package and version for this executable.
      const guess = basename(execPath);
      const pkg = rows(db, 'SELECT name, version FROM packages WHERE name = ?', [guess]);
      let packageName: string | null = null;
      let version: string | null = null;
      if (pkg.length > 0) {
        packageName = String(pkg[0].name);
        version = String(pkg[0].version);
      }
      records.push({
        unit: String(service.unit),
        exec_path: execPath,
        enabled: Number(service.enabled) === 1,
        package: packageName,
        version,
      });
    }
    return records;
  } finally {
    db.close();
  }
}

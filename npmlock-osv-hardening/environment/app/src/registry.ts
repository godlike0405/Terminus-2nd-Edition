// Offline registry snapshot: the set of published versions available for each
// package, from which a safe upgrade target is chosen. The snapshot is a JSON
// object mapping package name to an array of version strings.

import { readFileSync } from 'node:fs';

export type Registry = Record<string, string[]>;

export function loadRegistry(path: string): Registry {
  const data = JSON.parse(readFileSync(path, 'utf8')) as Registry;
  return data ?? {};
}

export function versionsOf(registry: Registry, name: string): string[] {
  return registry[name] ?? [];
}

// npm lockfile (lockfileVersion 3) parsing.
//
// This reader predates the nested-tree layout: it takes the installed set from
// the top-level `node_modules/<name>` entries and reads requirement ranges from
// the root project's `dependencies` only.

import { readFileSync } from 'node:fs';
import { compareCodePoints } from './canonical.js';

export interface InstalledPackage {
  name: string;
  version: string;
  paths: string[];
  production: boolean;
  constraints: string[];
}

interface LockNode {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, string>;
}

export function loadLockfile(path: string): InstalledPackage[] {
  const data = JSON.parse(readFileSync(path, 'utf8')) as { packages?: Record<string, LockNode> };
  const nodes = data.packages ?? {};

  const root = nodes[''] ?? {};
  const rootDeps = root.dependencies ?? {};

  const packages: InstalledPackage[] = [];
  for (const [key, node] of Object.entries(nodes)) {
    if (key === '' || node.version === undefined) continue;
    const segments = key.split('/');
    const name = segments[segments.length - 1];
    packages.push({
      name,
      version: node.version,
      paths: [key],
      production: node.dev !== true,
      constraints: rootDeps[name] !== undefined ? [rootDeps[name]] : [],
    });
  }
  packages.sort((a, b) => compareCodePoints(a.name, b.name));
  return packages;
}

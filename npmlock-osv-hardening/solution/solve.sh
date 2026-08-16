#!/usr/bin/env bash
set -euo pipefail

# Rewrites the four incomplete modules so npmguard compares versions by Semantic
# Versioning precedence, satisfies npm ranges, walks OSV SEMVER advisory
# intervals, resolves the full lockfile model, and emits the remediation
# artifacts at the paths the contract requires. The remaining modules are
# already correct.

cd "${APP_DIR:-/app}"

cat > src/semver.ts <<'EOF_semver'
// Semantic Versioning 2.0.0 precedence and npm range satisfaction.
//
// Versions compare by [major, minor, patch] then pre-release precedence (a
// pre-release version is lower than its associated release; identifiers compare
// numerically when both numeric, otherwise lexically; a larger identifier set
// wins when all shared identifiers are equal). Build metadata is ignored.
//
// Ranges are the npm range grammar: `||` unions of space-joined comparator sets,
// where each comparator is a caret (`^`), tilde (`~`), hyphen (`a - b`), x-range
// (`1.2.x`, `1.x`, `*`), exact version, or an operator comparator (`>=`, `>`,
// `<`, `<=`, `=`). A version carrying a pre-release tag satisfies a comparator
// set only when some comparator in that set is itself a pre-release with the same
// [major, minor, patch] tuple.

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: (string | number)[];
}

const CORE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parsePrerelease(text: string | undefined): (string | number)[] {
  if (text === undefined || text === '') return [];
  return text.split('.').map((identifier) => (/^\d+$/.test(identifier) ? Number(identifier) : identifier));
}

export function parse(version: string): SemVer {
  const match = CORE.exec(version.trim());
  if (match === null) throw new Error(`invalid semantic version: ${version}`);
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: parsePrerelease(match[4]),
  };
}

function compareIdentifiers(a: string | number, b: string | number): number {
  const aNumber = typeof a === 'number';
  const bNumber = typeof b === 'number';
  if (aNumber && bNumber) return a < b ? -1 : a > b ? 1 : 0;
  if (aNumber) return -1;
  if (bNumber) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function comparePrerelease(a: (string | number)[], b: (string | number)[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = compareIdentifiers(a[index], b[index]);
    if (difference !== 0) return difference;
  }
  return a.length < b.length ? -1 : a.length > b.length ? 1 : 0;
}

export function compare(left: SemVer, right: SemVer): number {
  if (left.major !== right.major) return left.major < right.major ? -1 : 1;
  if (left.minor !== right.minor) return left.minor < right.minor ? -1 : 1;
  if (left.patch !== right.patch) return left.patch < right.patch ? -1 : 1;
  return comparePrerelease(left.prerelease, right.prerelease);
}

export function compareVersions(left: string, right: string): number {
  return compare(parse(left), parse(right));
}

// --------------------------------------------------------------------------- //
// Range parsing
// --------------------------------------------------------------------------- //
type Op = '>' | '>=' | '<' | '<=' | '=';
interface Comparator {
  any: boolean;
  op: Op;
  ver: SemVer;
}

const ANY: Comparator = { any: true, op: '=', ver: { major: 0, minor: 0, patch: 0, prerelease: [] } };

function xr(component: string): number | null {
  if (component === '' || component === '*' || component === 'x' || component === 'X') return null;
  return Number(component);
}

interface Partial {
  major: number | null;
  minor: number | null;
  patch: number | null;
  prerelease: (string | number)[];
}

function parsePartial(text: string): Partial {
  let core = text;
  let prerelease: (string | number)[] = [];
  const plus = core.indexOf('+');
  if (plus >= 0) core = core.slice(0, plus);
  const dash = core.indexOf('-');
  if (dash >= 0) {
    prerelease = parsePrerelease(core.slice(dash + 1));
    core = core.slice(0, dash);
  }
  const parts = core.split('.');
  return {
    major: xr(parts[0] ?? ''),
    minor: xr(parts[1] ?? ''),
    patch: xr(parts[2] ?? ''),
    prerelease,
  };
}

function ver(major: number, minor: number, patch: number, prerelease: (string | number)[] = []): SemVer {
  return { major, minor, patch, prerelease };
}

function comparator(op: Op, v: SemVer): Comparator {
  return { any: false, op, ver: v };
}

function caret(text: string): Comparator[] {
  const p = parsePartial(text);
  if (p.major === null) return [ANY];
  const lowMinor = p.minor ?? 0;
  const lowPatch = p.patch ?? 0;
  const low = comparator('>=', ver(p.major, lowMinor, lowPatch, p.patch !== null ? p.prerelease : []));
  let high: Comparator;
  if (p.major !== 0) {
    high = comparator('<', ver(p.major + 1, 0, 0));
  } else if (p.minor === null) {
    high = comparator('<', ver(1, 0, 0));
  } else if (p.minor !== 0) {
    high = comparator('<', ver(0, p.minor + 1, 0));
  } else if (p.patch === null) {
    high = comparator('<', ver(0, 1, 0));
  } else {
    high = comparator('<', ver(0, 0, p.patch + 1));
  }
  return [low, high];
}

function tilde(text: string): Comparator[] {
  const p = parsePartial(text);
  if (p.major === null) return [ANY];
  const low = comparator('>=', ver(p.major, p.minor ?? 0, p.patch ?? 0, p.patch !== null ? p.prerelease : []));
  let high: Comparator;
  if (p.minor === null) {
    high = comparator('<', ver(p.major + 1, 0, 0));
  } else {
    high = comparator('<', ver(p.major, p.minor + 1, 0));
  }
  return [low, high];
}

function xrange(op: Op, text: string): Comparator[] {
  const p = parsePartial(text);
  if (p.major === null) {
    // A bare '*' with an equality intent matches any version; with an inequality
    // it degenerates to comparing against 0.0.0.
    if (op === '=' || op === '>=' || op === '<=') return [ANY];
    return [comparator(op, ver(0, 0, 0))];
  }
  if (p.minor === null) {
    if (op === '=') return [comparator('>=', ver(p.major, 0, 0)), comparator('<', ver(p.major + 1, 0, 0))];
    if (op === '>') return [comparator('>=', ver(p.major + 1, 0, 0))];
    if (op === '<=') return [comparator('<', ver(p.major + 1, 0, 0))];
    return [comparator(op, ver(p.major, 0, 0))];
  }
  if (p.patch === null) {
    if (op === '=') return [comparator('>=', ver(p.major, p.minor, 0)), comparator('<', ver(p.major, p.minor + 1, 0))];
    if (op === '>') return [comparator('>=', ver(p.major, p.minor + 1, 0))];
    if (op === '<=') return [comparator('<', ver(p.major, p.minor + 1, 0))];
    return [comparator(op, ver(p.major, p.minor, 0))];
  }
  return [comparator(op, ver(p.major, p.minor, p.patch, p.prerelease))];
}

function hyphen(lower: string, upper: string): Comparator[] {
  const low = parsePartial(lower);
  const high = parsePartial(upper);
  const lowComparator = comparator('>=', ver(low.major ?? 0, low.minor ?? 0, low.patch ?? 0, low.prerelease));
  let highComparator: Comparator;
  if (high.minor === null) {
    highComparator = comparator('<', ver((high.major ?? 0) + 1, 0, 0));
  } else if (high.patch === null) {
    highComparator = comparator('<', ver(high.major ?? 0, high.minor + 1, 0));
  } else {
    highComparator = comparator('<=', ver(high.major ?? 0, high.minor, high.patch, high.prerelease));
  }
  return [lowComparator, highComparator];
}

function parseComparatorSet(text: string): Comparator[] {
  const trimmed = text.trim();
  if (trimmed === '' || trimmed === '*') return [ANY];

  const tokens = trimmed.split(/\s+/);
  const hyphenIndex = tokens.indexOf('-');
  if (hyphenIndex === 1 && tokens.length === 3) {
    return hyphen(tokens[0], tokens[2]);
  }

  const comparators: Comparator[] = [];
  for (const token of tokens) {
    if (token === '') continue;
    if (token.startsWith('^')) {
      comparators.push(...caret(token.slice(1)));
    } else if (token.startsWith('~')) {
      comparators.push(...tilde(token.slice(1)));
    } else if (token.startsWith('>=')) {
      comparators.push(...xrange('>=', token.slice(2)));
    } else if (token.startsWith('<=')) {
      comparators.push(...xrange('<=', token.slice(2)));
    } else if (token.startsWith('>')) {
      comparators.push(...xrange('>', token.slice(1)));
    } else if (token.startsWith('<')) {
      comparators.push(...xrange('<', token.slice(1)));
    } else if (token.startsWith('=')) {
      comparators.push(...xrange('=', token.slice(1)));
    } else {
      comparators.push(...xrange('=', token));
    }
  }
  return comparators.length > 0 ? comparators : [ANY];
}

function testComparator(c: Comparator, version: SemVer): boolean {
  if (c.any) return true;
  const cmp = compare(version, c.ver);
  switch (c.op) {
    case '=':
      return cmp === 0;
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
  }
}

function testSet(comparators: Comparator[], version: SemVer): boolean {
  for (const c of comparators) {
    if (!testComparator(c, version)) return false;
  }
  if (version.prerelease.length > 0) {
    let allowed = false;
    for (const c of comparators) {
      if (c.any) continue;
      if (
        c.ver.prerelease.length > 0 &&
        c.ver.major === version.major &&
        c.ver.minor === version.minor &&
        c.ver.patch === version.patch
      ) {
        allowed = true;
      }
    }
    if (!allowed) return false;
  }
  return true;
}

export function satisfies(version: string, range: string): boolean {
  const parsed = parse(version);
  const groups = range.split('||');
  for (const group of groups) {
    if (testSet(parseComparatorSet(group), parsed)) return true;
  }
  return false;
}
EOF_semver

cat > src/osv.ts <<'EOF_osv'
// OSV advisory client and version-range containment for the npm ecosystem.
//
// Advisories are fetched from an OSV-compatible API with POST /v1/query and a
// {package:{name,ecosystem:"npm"}} body. Containment follows OSV SEMVER range
// semantics over Semantic Versioning precedence: a range's events form
// (introduced, fixed | last_affected | open) intervals in sequence; a version is
// affected when it falls in one of those intervals, and a "fixed" interval
// reports the version that clears it.

import { compareVersions } from './semver.js';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
}

export interface OsvVuln {
  id: string;
  withdrawn?: string;
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
}

type Interval = { introduced: string; kind: 'fixed' | 'last_affected' | 'open'; end: string | null };

function intervals(events: OsvEvent[]): Interval[] {
  const result: Interval[] = [];
  let introduced: string | null = null;
  for (const event of events) {
    if (event.introduced !== undefined) {
      introduced = event.introduced;
    } else if (event.fixed !== undefined) {
      result.push({ introduced: introduced ?? '0.0.0', kind: 'fixed', end: event.fixed });
      introduced = null;
    } else if (event.last_affected !== undefined) {
      result.push({ introduced: introduced ?? '0.0.0', kind: 'last_affected', end: event.last_affected });
      introduced = null;
    }
  }
  if (introduced !== null) result.push({ introduced, kind: 'open', end: null });
  return result;
}

function normalizeBound(bound: string): string {
  return bound === '0' ? '0.0.0' : bound;
}

function rangeHit(events: OsvEvent[], version: string): { hit: boolean; fixed: string | null } {
  for (const interval of intervals(events)) {
    const lower = normalizeBound(interval.introduced);
    if (compareVersions(version, lower) < 0) continue;
    if (interval.kind === 'open') return { hit: true, fixed: null };
    if (interval.kind === 'fixed') {
      if (compareVersions(version, interval.end as string) < 0) return { hit: true, fixed: interval.end };
    } else if (compareVersions(version, interval.end as string) <= 0) {
      return { hit: true, fixed: null };
    }
  }
  return { hit: false, fixed: null };
}

// Whether an advisory applies to package@version, and the fixed version of the
// containing interval when one exists. Withdrawn advisories, non-SEMVER ranges,
// and affected blocks for other packages or ecosystems never apply.
export function advisoryHit(
  vuln: OsvVuln,
  packageName: string,
  version: string,
): { hit: boolean; fixed: string | null } {
  if (vuln.withdrawn !== undefined) return { hit: false, fixed: null };
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== packageName || affected.package?.ecosystem !== 'npm') continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER') continue;
      const result = rangeHit(range.events ?? [], version);
      if (result.hit) return result;
    }
  }
  return { hit: false, fixed: null };
}

export async function queryOsv(base: string, packageName: string): Promise<OsvVuln[]> {
  const response = await fetch(`${base}/v1/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' } }),
  });
  if (!response.ok) {
    throw new Error(`OSV query for ${packageName} failed with status ${response.status}`);
  }
  const data = (await response.json()) as { vulns?: OsvVuln[] };
  return data.vulns ?? [];
}
EOF_osv

cat > src/lockfile.ts <<'EOF_lockfile'
// npm lockfile (lockfileVersion 3) parsing.
//
// The `packages` object maps a node path to an installed node. The root project
// is the empty-string key; every other key is a `node_modules/...`-nested path
// whose final segment (a scoped name keeps its `@scope/` prefix) is the package
// name. Each node carries its resolved `version`, a `dev`/`optional` flag, and a
// `dependencies` object of name -> semver range requirements.
//
// A package is in production scope when at least one of its installed nodes is
// neither a dev nor an optional dependency. The requirement ranges for a package
// are gathered from every `dependencies` entry that names it anywhere in the
// tree, including the root project's own dependencies.

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

function nameFromPath(key: string): string {
  const marker = 'node_modules/';
  const index = key.lastIndexOf(marker);
  return index >= 0 ? key.slice(index + marker.length) : key;
}

function pathDepth(key: string): number {
  return key.split('/').length;
}

export function loadLockfile(path: string): InstalledPackage[] {
  const data = JSON.parse(readFileSync(path, 'utf8')) as { packages?: Record<string, LockNode> };
  const nodes = data.packages ?? {};

  const constraints = new Map<string, Set<string>>();
  for (const node of Object.values(nodes)) {
    for (const [depName, range] of Object.entries(node.dependencies ?? {})) {
      if (!constraints.has(depName)) constraints.set(depName, new Set());
      constraints.get(depName)!.add(range);
    }
  }

  interface Aggregate {
    versions: { version: string; depth: number; path: string }[];
    paths: string[];
    production: boolean;
  }
  const byName = new Map<string, Aggregate>();
  for (const [key, node] of Object.entries(nodes)) {
    if (key === '' || node.version === undefined) continue;
    const name = nameFromPath(key);
    if (!byName.has(name)) byName.set(name, { versions: [], paths: [], production: false });
    const aggregate = byName.get(name)!;
    aggregate.versions.push({ version: node.version, depth: pathDepth(key), path: key });
    aggregate.paths.push(key);
    if (node.dev !== true && node.optional !== true) aggregate.production = true;
  }

  const packages: InstalledPackage[] = [];
  for (const [name, aggregate] of byName) {
    const chosen = [...aggregate.versions].sort(
      (a, b) => a.depth - b.depth || compareCodePoints(a.path, b.path),
    )[0];
    packages.push({
      name,
      version: chosen.version,
      paths: [...aggregate.paths].sort(compareCodePoints),
      production: aggregate.production,
      constraints: [...(constraints.get(name) ?? new Set<string>())].sort(compareCodePoints),
    });
  }
  packages.sort((a, b) => compareCodePoints(a.name, b.name));
  return packages;
}
EOF_lockfile

cat > src/report.ts <<'EOF_report'
// Artifact rendering.
//
// Writes, under the output directory:
//   remediation-report.json          (canonical JSON record of every finding)
//   overrides.json                   (an npm "overrides" map for the upgrades)
//   blocks/<name>.deny               (a quarantine stanza per blocked package)
//   remediation-audit.md             (Markdown audit note)
//
// A package name may be scoped (`@scope/name`); a `/` in the name becomes `__`
// in the block filename so it stays a single path segment.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalJson, compareCodePoints } from './canonical.js';
import type { Finding } from './remediate.js';

function writeFile(outDir: string, relative: string, contents: string): void {
  const full = join(outDir, relative);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents);
}

function blockFileName(name: string): string {
  return name.split('/').join('__');
}

export function overridesFor(findings: Finding[]): Record<string, string> {
  const overrides: Record<string, string> = {};
  for (const finding of findings) {
    if (finding.decision === 'upgrade' && finding.target_version !== null) {
      overrides[finding.name] = finding.target_version;
    }
  }
  return overrides;
}

function renderMarkdown(findings: Finding[]): string {
  const upgraded = findings.filter((f) => f.decision === 'upgrade').length;
  const blocked = findings.filter((f) => f.decision === 'block').length;
  const clean = findings.filter((f) => f.decision === 'ok').length;
  const lines = [
    '# npm dependency remediation audit',
    '',
    `Packages audited: ${findings.length}`,
    `Upgraded: ${upgraded}`,
    `Blocked: ${blocked}`,
    `Clean: ${clean}`,
    '',
  ];
  for (const finding of findings) {
    let verdict: string;
    if (finding.decision === 'upgrade') verdict = `UPGRADE to ${finding.target_version}`;
    else if (finding.decision === 'block') verdict = `BLOCKED (${finding.reason})`;
    else verdict = 'CLEAN';
    const advisories = finding.advisories.length > 0 ? finding.advisories.join(', ') : 'none';
    const constraints = finding.constraints.length > 0 ? finding.constraints.join(', ') : 'none';
    lines.push(
      `## ${finding.name}`,
      '',
      `- Installed: ${finding.installed_version}`,
      `- Decision: ${verdict}`,
      `- Advisories: ${advisories}`,
      `- Constraints: ${constraints}`,
      '',
    );
  }
  return lines.join('\n');
}

export function writeArtifacts(outDir: string, findings: Finding[]): void {
  const ordered = [...findings].sort((a, b) => compareCodePoints(a.name, b.name));
  const overrides = overridesFor(ordered);
  const blocked = ordered.filter((f) => f.decision === 'block').map((f) => f.name).sort(compareCodePoints);

  const report = {
    generated_by: 'npmguard',
    report_version: '1',
    packages: ordered,
    overrides,
    blocked,
  };
  writeFile(outDir, 'remediation-report.json', canonicalJson(report));
  writeFile(outDir, 'overrides.json', canonicalJson({ overrides }));

  for (const finding of ordered) {
    if (finding.decision === 'block') {
      writeFile(
        outDir,
        `blocks/${blockFileName(finding.name)}.deny`,
        `Package: ${finding.name}\nInstalled: ${finding.installed_version}\nReason: ${finding.reason}\nAction: manual-review\n`,
      );
    }
  }

  writeFile(outDir, 'remediation-audit.md', renderMarkdown(ordered));
}
EOF_report

# Recompile so /app/dist reflects the repaired sources.
npm run build

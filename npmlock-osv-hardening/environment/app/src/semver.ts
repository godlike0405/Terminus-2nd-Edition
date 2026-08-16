// Semantic Versioning precedence and npm range satisfaction.
//
// Carried over from the previous release line, which only ever shipped plain
// `major.minor.patch` versions and simple caret requirements. The comparison and
// range checks below still reflect that older, narrower world.

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: (string | number)[];
}

export function parse(version: string): SemVer {
  const core = version.trim().split('+')[0].split('-')[0];
  const parts = core.split('.');
  return {
    major: Number(parts[0] ?? '0'),
    minor: Number(parts[1] ?? '0'),
    patch: Number(parts[2] ?? '0'),
    prerelease: [],
  };
}

export function compare(left: SemVer, right: SemVer): number {
  if (left.major !== right.major) return left.major < right.major ? -1 : 1;
  if (left.minor !== right.minor) return left.minor < right.minor ? -1 : 1;
  if (left.patch !== right.patch) return left.patch < right.patch ? -1 : 1;
  return 0;
}

export function compareVersions(left: string, right: string): number {
  return compare(parse(left), parse(right));
}

// Requirement matching. Handles exact pins and carets by keeping the major fixed;
// the other range forms are treated as a lower bound.
export function satisfies(version: string, range: string): boolean {
  const target = parse(version);
  const text = range.trim();
  if (text === '' || text === '*') return true;
  if (text.startsWith('^')) {
    const base = parse(text.slice(1));
    return target.major === base.major && compare(target, base) >= 0;
  }
  if (text.startsWith('>=')) {
    return compare(target, parse(text.slice(2))) >= 0;
  }
  return compare(target, parse(text)) === 0;
}

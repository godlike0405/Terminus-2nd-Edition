// Canonical JSON: recursively key-sorted (by Unicode code point), compact, one
// trailing newline. Object key enumeration order in JavaScript is unreliable
// for integer-like keys, so this serializer never trusts insertion order.

export function compareCodePoints(left: string, right: string): number {
  const leftPoints = [...left];
  const rightPoints = [...right];
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftPoints[index].codePointAt(0)! - rightPoints[index].codePointAt(0)!;
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return leftPoints.length - rightPoints.length;
}

function serialize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  const kind = typeof value;
  if (kind === 'string' || kind === 'boolean') return JSON.stringify(value);
  if (kind === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  const record = value as Record<string, unknown>;
  const members: string[] = [];
  for (const key of Object.keys(record).sort(compareCodePoints)) {
    members.push(`${JSON.stringify(key)}:${serialize(record[key])}`);
  }
  return `{${members.join(',')}}`;
}

export function canonicalJson(value: unknown): string {
  return `${serialize(value)}\n`;
}

// Debian package version comparison.

export function compareDeb(left: string, right: string): number {
  const a = left.split('.').map((part) => Number.parseInt(part, 10));
  const b = right.split('.').map((part) => Number.parseInt(part, 10));
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const leftValue = Number.isNaN(a[index]) ? 0 : a[index] ?? 0;
    const rightValue = Number.isNaN(b[index]) ? 0 : b[index] ?? 0;
    if (leftValue !== rightValue) return leftValue < rightValue ? -1 : 1;
  }
  return 0;
}

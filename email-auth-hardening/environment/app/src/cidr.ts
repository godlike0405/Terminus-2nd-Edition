// IPv4 CIDR algebra. SPF authorization is ultimately a set of IPv4 ranges, so the
// tool needs to normalize prefixes (masking host bits), decide containment and
// overlap, and collapse a set of ranges to its minimal canonical form. All
// arithmetic is on unsigned 32-bit integers so the TypeScript tool and the Python
// grader agree exactly.

export interface Cidr {
  network: number;
  prefix: number;
}

function maskFor(prefix: number): number {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xffffffff;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

export function ipToInt(ip: string): number | null {
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const n = Number.parseInt(octet, 10);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

// cidrContainsIp reports whether a dotted IPv4 address falls inside a CIDR range.
export function cidrContainsIp(cidr: Cidr, ip: string): boolean {
  const value = ipToInt(ip);
  if (value === null) return false;
  return cidr.network <= value && value <= cidr.network + 2 ** (32 - cidr.prefix) - 1;
}

function intToIp(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

// parseCidr accepts "a.b.c.d" (a host address, treated as /32) or "a.b.c.d/p" and
// returns the range with its host bits cleared, or null when the token is not a
// well-formed IPv4 CIDR.
export function parseCidr(token: string): Cidr | null {
  const slash = token.indexOf('/');
  const ipPart = slash === -1 ? token : token.slice(0, slash);
  const prefixPart = slash === -1 ? '32' : token.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixPart)) return null;
  const prefix = Number.parseInt(prefixPart, 10);
  if (prefix > 32) return null;
  const value = ipToInt(ipPart);
  if (value === null) return null;
  const network = (value & maskFor(prefix)) >>> 0;
  return { network, prefix };
}

export function cidrString(cidr: Cidr): string {
  return `${intToIp(cidr.network)}/${cidr.prefix}`;
}

function rangeEnd(cidr: Cidr): number {
  return cidr.network + 2 ** (32 - cidr.prefix) - 1;
}

// contains reports whether `outer`'s range fully covers `inner`'s range.
export function contains(outer: Cidr, inner: Cidr): boolean {
  return outer.network <= inner.network && rangeEnd(inner) <= rangeEnd(outer);
}

// overlaps reports whether two ranges intersect at all.
export function overlaps(a: Cidr, b: Cidr): boolean {
  return a.network <= rangeEnd(b) && b.network <= rangeEnd(a);
}

export function compareCidr(a: Cidr, b: Cidr): number {
  if (a.network !== b.network) return a.network < b.network ? -1 : 1;
  return a.prefix - b.prefix;
}

// collapse returns the minimal canonical set: host bits masked, exact duplicates
// removed, any range that is fully covered by a shorter-prefix range dropped, and
// the survivors sorted by network then prefix.
export function collapse(cidrs: Cidr[]): Cidr[] {
  const uniq: Cidr[] = [];
  const seen = new Set<string>();
  for (const cidr of cidrs) {
    const key = `${cidr.network}/${cidr.prefix}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uniq.push(cidr);
  }
  const kept = uniq.filter(
    (cidr) => !uniq.some((other) => other.prefix < cidr.prefix && contains(other, cidr)),
  );
  return kept.sort(compareCidr);
}

// SPF hardening. The hardened record authorizes exactly the connecting IPs that
// legitimately evaluate to Pass for the domain today, as literal /32 ranges — minus
// any that overlap a flagged spoof-intel source — collapsed to canonical form and
// closed with the configured `all` qualifier, so it needs no DNS lookups.

import { collapse, overlaps, parseCidr, cidrString, type Cidr } from './cidr.js';
import type { FlaggedSource } from './feed.js';
import type { HardenConfig } from './model.js';

export interface HardenedSpf {
  authorized: Cidr[];
  removed: Cidr[];
  record: string;
}

export function hardenSpf(passingIps: string[], flagged: FlaggedSource[], config: HardenConfig): HardenedSpf {
  const raw: Cidr[] = [];
  for (const ip of passingIps) {
    const cidr = parseCidr(ip);
    if (cidr !== null) raw.push(cidr);
  }
  const authorized = collapse(raw);
  const flaggedCidrs: Cidr[] = [];
  for (const source of flagged) {
    const cidr = parseCidr(source.cidr);
    if (cidr !== null) flaggedCidrs.push(cidr);
  }
  const removed = authorized.filter((cidr) => flaggedCidrs.some((flag) => overlaps(cidr, flag)));
  const removedKeys = new Set(removed.map((cidr) => `${cidr.network}/${cidr.prefix}`));
  const kept = authorized.filter((cidr) => !removedKeys.has(`${cidr.network}/${cidr.prefix}`));
  const body = kept.map((cidr) => ` ip4:${cidrString(cidr)}`).join('');
  const record = `v=spf1${body} ${config.spfAll}`;
  return { authorized, removed, record };
}

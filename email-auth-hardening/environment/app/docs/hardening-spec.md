# mailguard contract

`mailguard` audits the email-authentication posture of a set of managed domains
against a batch of observed inbound connections. For every observation it evaluates
the connecting IP against the domain's published SPF record with the full RFC 7208
check-host() procedure; it scores each domain's SPF and DMARC posture; and it
hardens the SPF record down to exactly the sources that legitimately pass today,
plus a strict DMARC record. It writes a JSON report, the hardened records and a
Markdown audit. This document is the authority for every rule and every output byte.

## Invocation and configuration

`mailguard` takes no arguments. It reads six settings from the environment, each
with a default:

- `SCOPE_PATH` (`/app/data/scope.json`) — `{"domains": [...]}`, the managed domains.
- `PROBES_PATH` (`/app/data/probes.json`) — `{"probes": [{"id","domain","ip"}, ...]}`,
  the observed connections: a message id, the domain whose SPF governs it, and the
  connecting IPv4 address.
- `POLICY_PATH` (`/app/data/config.json`) — the hardening configuration: `rua` (the
  DMARC aggregate-report URI), `policy` (the target DMARC policy, `reject` or
  `quarantine`; any other value means `reject`), `spf_all` (the target SPF `all`
  qualifier, e.g. `-all`). Missing `rua` defaults to `mailto:dmarc-reports@localhost`;
  missing `spf_all` defaults to `-all`.
- `DNS_API_BASE` (`http://127.0.0.1:8785`), `FEED_API_BASE` (`http://127.0.0.1:8786`),
  `OUTPUT_DIR` (`/app/out`).

## DNS resolver and spoof-intel feed

Every lookup is a `GET {DNS_API_BASE}/resolve?name=<name>&type=<TXT|A|MX>` returning
`{"status","records"}` where `status` is `NOERROR` or `NXDOMAIN` and `records` is an
array of strings (TXT bodies, IPv4 addresses, or MX hostnames). A single
`GET {FEED_API_BASE}/v1/flagged` returns `{"sources": [{"cidr","reason"}, ...]}` of
flagged IPv4 networks; it is queried once and applies to every domain.

## SPF evaluation — check-host(domain, ip)

A domain's SPF record is the TXT record whose body (trimmed, lowercased) equals
`v=spf1` or begins `v=spf1 `. The record body is a whitespace-separated list of
terms. A term is a modifier `name=value` (`redirect`, `exp`; `exp` is ignored) or a
mechanism `[qualifier]name[:value][/len]` with qualifier `+ - ~ ?` (default `+`).

Evaluation walks the mechanisms **left to right** and returns the qualifier of the
**first mechanism that matches** — Pass for `+`, Fail for `-`, SoftFail for `~`,
Neutral for `?`. Matching:

- `all` — always matches.
- `ip4:<cidr>` — matches if the connecting IP is within the CIDR (a bare address is
  `/32`). `ip6` never matches.
- `a[:domain][/len]` — matches if the IP is within `<A-record>/len` for any A record
  of `domain` (or the current domain); default `len` is 32.
- `mx[:domain][/len]` — resolve the MX hostnames of `domain` (or the current domain),
  then their A records; matches under the same `/len` rule.
- `include:<domain>` — recursively evaluate check-host() for that domain and the same
  IP. The include **matches only if that evaluation returns Pass** (then this
  mechanism's qualifier is the result). If it returns Fail, SoftFail or Neutral the
  include does **not** match and evaluation continues to the next term. If it returns
  None (the target has no usable SPF record) or PermError, the whole evaluation is
  **PermError**.
- `exists:<macro>` — expand the macro string (below) and matches if the resulting
  name has any A record. (The qualifier is applied on match.)
- `ptr` — deprecated; never matches in this evaluator, but still consumes a lookup.
- `redirect=<domain>` — a modifier used only when no mechanism matched and the record
  has no `all`: the result is the target's check-host() result, except a None from the
  target becomes PermError. A record that contains an `all` mechanism ignores
  `redirect`.

If no mechanism matches, there is no `all`, and there is no usable `redirect`, the
result is **None**.

**Lookup budget.** Each `include`, `a`, `mx`, `ptr`, `exists` and an evaluated
`redirect` counts as one DNS lookup, in the order it is processed along the walk;
`all`, `ip4`, `ip6` count as zero. As soon as the count would exceed **10**, the
evaluation returns **PermError** and stops — so whether a record PermErrors depends on
the connecting IP (an early match may stop the walk before the limit). A recursive
`include`/`redirect` accumulates into the same budget; re-visiting a domain already on
the current evaluation path is PermError.

**Void budget.** A lookup is void when it returns NXDOMAIN or an empty record set (for
`a`/`exists` an empty A set, for `mx` an empty MX set). As soon as more than **2** void
lookups occur, the evaluation returns **PermError**. The A lookups performed for the
hostnames of an `mx` do not count toward either budget.

The report records, per observation, the final result
(`pass`/`fail`/`softfail`/`neutral`/`none`/`permerror`) and the number of DNS lookups
consumed on the path taken.

## Macro expansion (RFC 7208 section 7)

A macro is `%{<letter><digits?><r?><delimiters?>}`; `%%`, `%_`, `%-` expand to `%`, a
space and `%20`. Letters: `s` the sender (`local@domain`), `l` its local part, `o`/`d`
the domain, `i` the connecting IP dotted, `h` the domain, `v` the string `in-addr`.
The value is split on the delimiter characters (default `.`); a trailing `r` reverses
the parts; a leading digit count keeps only that many right-most parts; the parts are
rejoined with `.`. The sender is `probe@<domain>`. Thus `exists:%{ir}.dnsbl.example`
turns the IP `1.2.3.4` into the query `4.3.2.1.dnsbl.example`.

## Static record analysis and SPF weaknesses

Independently of any IP, each domain's record yields: `present`, `multiple` (more than
one SPF TXT), the deprecated-`ptr` flag, and the **effective all** — the qualifier
word (`pass`/`fail`/`softfail`/`neutral`) of the record's first `all` mechanism, or the
effective all of a `redirect` target when there is no `all`, or `none`.

SPF weakness codes (sorted, unique). If SPF is absent the only code is `spf_missing`.
Otherwise: `spf_multiple_records`; `spf_permissive_all` / `spf_neutral_all` /
`spf_softfail` / `spf_no_all` when the effective all is pass / neutral / softfail /
none; `spf_deprecated_ptr` (any `ptr`); `spf_permerror_observed` (at least one of the
domain's observations evaluated to PermError); `spf_flagged_source` (the hardening step
removed at least one passing source for this domain).

## IPv4 CIDR canonicalization and SPF hardening

Ranges are masked to the network address and rendered `a.b.c.d/p`. The **collapsed**
form of a set masks each range, drops exact duplicates, drops any range covered by a
shorter-prefix range, and sorts by network then prefix. Two ranges **overlap** when
their intervals intersect.

For each domain, the hardened SPF record authorizes exactly the connecting IPs whose
observations evaluated to **Pass**, each as a `/32`, collapsed — minus any range that
overlaps a flagged feed CIDR (`removed_sources`; their presence raises
`spf_flagged_source`). The record is `v=spf1` followed by ` ip4:<cidr>` for every kept
range in collapsed order, then a space and the configured `spf_all` — e.g.
`v=spf1 ip4:198.51.100.5/32 -all`, or `v=spf1 -all` when nothing passes.

## DMARC

A domain's DMARC record is the TXT at `_dmarc.<domain>` beginning (trimmed, lowercased)
`v=dmarc1`, a `;`-separated list of `key=value` tags (first of each key wins).
Recognized: `p`/`sp` (`none`/`quarantine`/`reject`; other or missing is `none`), `pct`
(integer, default 100), `adkim`/`aspf` (`s`/`r`, default `r`), `rua`. Effective
subdomain policy is `sp` if present else `p`. Weakness codes (sorted): `dmarc_missing`;
`dmarc_policy_none` (`p`=none); `dmarc_policy_quarantine`; `dmarc_subdomain_gap` (an
explicit `sp` that is not `reject`); `dmarc_partial_pct` (`pct`<100);
`dmarc_relaxed_alignment` (`adkim` or `aspf` is `r`); `dmarc_rua_missing`. The hardened
record is exactly `v=DMARC1; p=<P>; sp=<P>; adkim=s; aspf=s; pct=100; rua=<RUA>` for
the configured `policy` and `rua`.

## Artifacts

All under `OUTPUT_DIR`. Observations appear sorted by `id`; domains sorted by name
(ascending Unicode code point).

- `email-auth-report.json` — canonical JSON: recursively key-sorted, compact
  (`,`/`:` separators), UTF-8, exactly one trailing newline. `report_version` is the
  string `"1"`; `lookups`, `pass_count`, `permerror_count`, `pct` and the `summary`
  counters are integers; `present` is a boolean. `summary.spf_pass` /
  `summary.spf_permerror` count observations with that result; `summary.dmarc_weak`
  counts domains with a non-empty DMARC weakness list; `summary.flagged_sources_removed`
  is the total removed across all domains. Example:

```json
{"domains":[{"dmarc":{"adkim":"r","aspf":"r","hardened_record":"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:agg@sec.example","pct":100,"policy":"none","present":true,"subdomain_policy":"none","weaknesses":["dmarc_policy_none","dmarc_relaxed_alignment","dmarc_rua_missing"]},"domain":"shop.example","spf":{"effective_all":"fail","hardened_record":"v=spf1 ip4:198.51.100.5/32 -all","pass_count":1,"permerror_count":0,"present":true,"weaknesses":[]}}],"generated_by":"mailguard","observations":[{"domain":"shop.example","id":"m001","ip":"198.51.100.5","lookups":0,"spf_result":"pass"}],"report_version":"1","summary":{"dmarc_weak":1,"domains":1,"flagged_sources_removed":0,"observations":1,"spf_pass":1,"spf_permerror":0}}
```

- `zones/<domain>/spf.txt`, `zones/<domain>/dmarc.txt` — the hardened records, each
  plus one trailing newline.
- `email-auth-audit.md`:

```
# Email authentication hardening audit

Domains assessed: <N>
Observations evaluated: <M>
SPF records with weaknesses: <count>
DMARC records with weaknesses: <count>
Flagged sources removed: <total>

## <domain>

SPF: effective all <word>, pass <p>, permerror <pe>, weaknesses <list>
DMARC: policy <p>, weaknesses <list>
```

`<list>` is the weakness codes joined by a comma and a space (`", "`), or the literal
`none`. A single blank line separates the summary block from the first section and each
consecutive pair of sections, which follow the sorted domain order; the file ends with
the last section's `DMARC:` line and exactly one trailing newline.

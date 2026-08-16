# certguard — TLS service hardening contract

`certguard` reads a host's TLS inventory, validates the certificate chain behind
each TLS service against the host's trust store and a revocation service, and
writes the configuration artifacts that bring the host into a hardened state: it
rotates a service onto a valid replacement certificate when its bound
certificate can no longer be trusted, disables a service that has no usable
certificate, and leaves compliant services untouched. This document is the
contract every run must satisfy.

## Inputs

All evaluation happens **as of a fixed instant** `T` (never the wall clock).

**Inventory** — a directory (`INVENTORY_DIR`, default `/app/data/inventory`)
holding four JSON documents:

- `policy.json` — `{ "evaluated_at": <rfc3339-utc>, "rotation_window_days": <int> }`.
  `evaluated_at` is the instant `T`. A certificate is *expiring* when it is valid
  at `T` but fewer than `rotation_window_days` days remain before its
  `not_after` (i.e. `not_after - T < rotation_window_days`, using a day of
  exactly 86400 seconds).
- `trust-store.json` — a JSON array of `subject_key_id` hex strings; a
  certificate is a **trusted anchor** exactly when its `subject_key_id` appears
  here.
- `certificates.json` — a JSON array of certificate objects (see below); it holds
  every certificate present on the host — leaves, intermediates and roots.
- `services.json` — a JSON array of TLS services, each
  `{ "unit": <systemd-unit>, "server_name": <dns-name>, "bound_id": <cert-id>,
  "enabled": <bool> }`. `bound_id` is the `id` of the certificate the service
  currently serves.

A **certificate object** has these fields:

- `id` — an opaque unique string used only for binding and reference.
- `subject` — the certificate subject (a DNS name for leaves).
- `subject_key_id` (`ski`) and `authority_key_id` (`aki`) — hex strings. The
  issuer of a certificate is the certificate whose `subject_key_id` equals this
  certificate's `authority_key_id`. A self-issued certificate has `aki == ski`.
  **Subject key ids are unique within an inventory**, so a certificate has at
  most one issuer present.
- `serial` — the certificate serial as a nonnegative integer, written either in
  decimal (`"4660"`) or `0x`-prefixed hexadecimal (`"0x1234"`).
- `not_before`, `not_after` — RFC 3339 UTC validity bounds (inclusive).
- `is_ca` — boolean.
- `path_len` — for a CA, the maximum number of intermediate CA certificates that
  may appear below it in a chain; `null` means unconstrained. Ignored for
  non-CAs.
- `key_usages` — array of usage strings; a CA must carry `certSign` to issue.
- `ext_key_usages` — array of extended-key-usage strings. An empty array means
  unrestricted.
- `sans` — array of DNS subject-alternative names (leaves).
- `name_constraints` — for a CA, optionally
  `{ "permitted": [<dns>...], "excluded": [<dns>...] }`; absent means no
  constraint.

**Revocation service** — an HTTP service at `REVOCATION_API_BASE` (default
`http://127.0.0.1:8730`). A `POST /v1/revocations` with body
`{"issuer_key_id": <ski-hex>}` returns `{"crl": <crl-or-null>}`, where a CRL is
`{ "issuer_key_id": <hex>, "this_update": <rfc3339>, "next_update": <rfc3339>,
"entries": [ {"serial": <dec-or-hex>, "reason": <string>} ... ] }`. A `null` CRL
means the issuer publishes no revocation data. A local mirror over the shipped
CRLs in `/app/vendor-crl` can be started with `go run ./tools/crlserver`.

## Serial and fingerprint normalization

A **normalized serial** is the certificate serial's integer value rendered in
lowercase hexadecimal with no `0x` prefix and no leading zeros (`0` stays `"0"`).
Serials — in certificates and in CRL entries — are compared by value, so
`"0x1234"`, `"4660"` and `"0000004660"` all denote the same serial.

A certificate's **fingerprint** is `sha256:` followed by the lowercase-hex
SHA-256 of the canonical JSON encoding (recursively key-sorted, compact `,`/`:`
separators, **no trailing newline**, UTF-8) of exactly this object:

```
{ "aki": <aki>, "eku": <ext_key_usages, in order>, "is_ca": <bool>,
  "ku": <key_usages, in order>, "name_constraints": <object or null>,
  "not_after": <not_after>, "not_before": <not_before>, "path_len": <int or null>,
  "sans": <sans, in order>, "serial": <normalized serial>, "ski": <ski>,
  "subject": <subject> }
```

When `name_constraints` is present it is encoded as
`{ "excluded": [...], "permitted": [...] }` with both keys always present (an
absent list becomes `[]`); when absent from the certificate it is encoded as
`null`. Arrays preserve their inventory order. The 64-hex-character portion after
`sha256:` is the certificate's **fp-hex**, used in artifact file paths.

## Chain building

For a leaf `L` (a certificate with `is_ca == false`), build the chain by
following issuers: starting at `L`, repeatedly look up the certificate whose
`subject_key_id` equals the current certificate's `authority_key_id`, appending
it, and stop as soon as the appended certificate's `subject_key_id` is a trusted
anchor, or when no issuer is present, or when a `subject_key_id` would repeat
(a loop). The chain is **anchored** iff some certificate on it is a trusted
anchor; the anchor is the first such certificate walking up from the leaf, and
certificates above the anchor are discarded. The **chain** is `L` (index 0) up
to and including that anchor. Because subject key ids are unique, each leaf has at
most one chain.

## Chain validation

A chain `C[0..n]` (`C[0]` the leaf, `C[n]` the anchor) is **structurally valid**
as of `T` for a service whose identity is `server_name` iff **all** hold:

1. **Anchored** — `C[n].subject_key_id` is a trusted anchor.
2. **Issuance** — for every `i > 0`, `C[i].is_ca` is true and `C[i].key_usages`
   contains `certSign`.
3. **Validity** — for every certificate *except the anchor* `C[n]`,
   `not_before <= T <= not_after`. The anchor's own validity window is not
   checked.
4. **Path length** — for every CA `C[i]` (`i >= 1`) with a non-null `path_len`
   `p`, the number of certificates strictly between the leaf and `C[i]` — that
   is `i - 1` — must be `<= p`.
5. **Extended key usage** — for every certificate on the chain whose
   `ext_key_usages` is non-empty, it must contain `serverAuth` or
   `anyExtendedKeyUsage`.
6. **Server identity** — some entry of `C[0].sans` matches `server_name`. A SAN
   matches by case-insensitive comparison either exactly, or as a wildcard
   `*.suffix` that matches a name with the **same number of labels** whose
   labels after the first equal `suffix` (`*.a.com` matches `x.a.com`, but not
   `a.com` and not `x.y.a.com`). A `*` may appear only as the whole leftmost
   label.
7. **Name constraints** — for every CA `C[i]` (`i >= 1`) carrying
   `name_constraints`, `server_name` must, when `permitted` is non-empty, match
   at least one permitted subtree, and must match no `excluded` subtree. A DNS
   name matches subtree `S` when it equals `S` or ends with `"." + S`
   (case-insensitive); `example.com` matches `example.com` and `a.example.com`.

A structurally valid chain is **revocation-clean** iff every non-anchor
certificate `C[i]` (`0 <= i < n`) passes the revocation check against the CRL of
its issuer `C[i].authority_key_id` (see below). A leaf is **usable** iff its
chain is structurally valid and revocation-clean.

## Revocation

For an issuer key id `k`, `certguard` queries `POST /v1/revocations` once (results
are cached; each distinct issuer key id is queried at most once). Given the
returned CRL and the certificate serial `s`:

- **No CRL** (`null`) — not revoked.
- **Stale CRL** — if `T < this_update` or `T > next_update`, revocation status is
  unknown and the certificate is treated as **revoked** (fail-closed).
- **Current CRL** — the certificate is revoked iff some entry has serial equal to
  `s` (by value) **and** a `reason` other than `removeFromCRL`; an entry whose
  `reason` is `removeFromCRL` un-revokes that serial and is ignored.

For every in-scope service, `certguard` consults the revocation service for the
issuer (`authority_key_id`) of **every** non-anchor certificate on the anchored
chain of each **relevant leaf** — the service's bound certificate (when it is a
leaf present in the inventory) and every leaf whose SANs cover the service's
`server_name`. It queries each distinct issuer key id exactly once (results are
cached) and does **not** skip an issuer because a certificate earlier on the
chain was already found revoked; a leaf whose chain is not anchored contributes
no query. The set of issuers queried therefore depends only on certificate
linkage, the trust store and the service identities — never on validity dates or
revocation outcomes.

## Scope, decision policy and selection

A service is **in scope** when its `server_name` is non-empty; every service in
`services.json` is in scope. For each service, classify its bound certificate
`bound_id` as of `T` and choose a decision.

The bound certificate's **status** is the first that applies:

1. `missing` — no certificate has `id == bound_id`, or that certificate is a CA
   (`is_ca == true`).
2. `expired` — the bound leaf's own window excludes `T` (`T < not_before` or
   `T > not_after`).
3. `untrusted` — the bound leaf's chain is not structurally valid (unanchored,
   or fails issuance, path length, EKU, server identity, name constraints, or an
   intermediate is outside its validity window).
4. `revoked` — the chain is structurally valid but not revocation-clean.
5. `expiring` — the leaf is usable but expiring (see `rotation_window_days`).
6. `compliant` — the leaf is usable and not expiring.

A **replacement candidate** for a service is any leaf that is usable for the
service's `server_name` **and** not expiring (a fully valid, non-expiring leaf
covering the identity). The **best replacement** is chosen by, in order: latest
`not_after`; then largest serial by value; then largest fp-hex
lexicographically. The bound leaf itself is eligible as a candidate when it
qualifies.

Decisions:

- **ok** — status `compliant`. `reason` is `compliant`. No artifact.
- **rotate** — status is not `compliant` and a best replacement exists. `reason`
  is the bound status (`missing`, `expired`, `untrusted`, `revoked` or
  `expiring`). The service is rotated onto the best replacement.
- **block** — status is not `compliant` and no replacement candidate exists.
  `reason` is the bound status. The unit is disabled.

## Output artifacts

All paths are relative to `OUTPUT_DIR` (default `/app/out`).

**nginx rotation snippet** — one per rotated service, at
`nginx/snippets/<unit>.conf`, pointing the service at the chosen replacement by
its fp-hex:

```
# certguard: rotated <unit> (<reason>)
ssl_certificate     /etc/certguard/certs/<fp-hex>.pem;
ssl_certificate_key /etc/certguard/private/<fp-hex>.key;
```

**systemd override** — one per blocked service, at
`systemd/system/<unit>.d/override.conf` (a templated unit such as
`tls@.service` uses the directory `tls@.service.d`):

```
[Service]
ExecStart=
ExecStart=/bin/false
NoNewPrivileges=yes
ProtectSystem=strict
```

**Trust report** — `tls-trust-report.json`, canonical JSON: object keys sorted
recursively by Unicode code point, compact `,`/`:` separators, exactly one
trailing newline. Top-level keys are `blocked_units` (sorted array of unit
strings), `evaluated_at` (the JSON string `T`), `generated_by` (the JSON string
`"certguard"`), `report_version` (the JSON string `"1"`), `rotations` (array of
`{"fingerprint","unit"}` objects sorted by unit) and `services`. Each `services`
entry, sorted by `unit`, holds `anchored` (JSON boolean — whether the bound
leaf's chain reached a trusted anchor), `bound_fingerprint` (string or `null`),
`bound_id` (string), `bound_not_after` (string or `null`), `chain` (array of
fingerprint strings from leaf to anchor, `[]` when there is no bound chain),
`decision` (`"ok"`, `"rotate"` or `"block"`), `enabled` (JSON boolean),
`reason` (string), `replacement_fingerprint` (string or `null`), `server_name`
(string) and `unit` (string).

The example below is shown indented for readability; the file itself is the
canonical (compact, recursively key-sorted, newline-terminated) form of the same
value, and it fixes the exact JSON type of every field.

```json
{
  "blocked_units": ["legacy.service"],
  "evaluated_at": "2026-07-01T00:00:00Z",
  "generated_by": "certguard",
  "report_version": "1",
  "rotations": [
    { "fingerprint": "sha256:9f2c...b1", "unit": "web.service" }
  ],
  "services": [
    {
      "anchored": true,
      "bound_fingerprint": "sha256:1a3d...4e",
      "bound_id": "leaf-web-2025",
      "bound_not_after": "2026-07-20T00:00:00Z",
      "chain": ["sha256:1a3d...4e", "sha256:aa11...09"],
      "decision": "rotate",
      "enabled": true,
      "reason": "expiring",
      "replacement_fingerprint": "sha256:9f2c...b1",
      "server_name": "web.example.com",
      "unit": "web.service"
    },
    {
      "anchored": false,
      "bound_fingerprint": null,
      "bound_id": "leaf-legacy",
      "bound_not_after": null,
      "chain": [],
      "decision": "block",
      "enabled": true,
      "reason": "missing",
      "replacement_fingerprint": null,
      "server_name": "legacy.example.com",
      "unit": "legacy.service"
    }
  ]
}
```

`bound_fingerprint`, `bound_not_after` and every `chain` entry are `null`/empty
whenever the bound certificate is `missing`. `replacement_fingerprint` is the
chosen replacement's fingerprint for a rotate and `null` otherwise. `anchored`
reflects the bound leaf's own chain, independent of the decision.

**Audit note** — `tls-rotation-audit.md`:

```
# TLS service rotation audit

Evaluated at: <T>
Services scanned: <n>
Rotated: <r>
Blocked: <b>
Compliant: <c>

## <unit>

- Server name: <server_name>
- Bound certificate: <bound_id>
- Chain: <fp-hex > fp-hex > ... leaf to anchor, or "none">
- Decision: <ROTATED to <fp-hex> | BLOCKED (<reason>) | COMPLIANT>
```

Units appear in sorted order, one `##` section each, separated by a blank line,
with a trailing newline at end of file. The `Chain` line joins the chain's
fp-hex values (the 64-character portions, without the `sha256:` prefix) with
`" > "`, leaf first; it is `none` when the bound chain is empty.

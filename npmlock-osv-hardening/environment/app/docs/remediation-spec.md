# npm dependency remediation — contract

`npmguard` reads a project's npm lockfile, checks every production dependency
against the OSV advisory API, chooses the smallest safe upgrade that still
satisfies the tree's version requirements, and writes the remediation artifacts.
This document is the contract every run must satisfy.

## Inputs

**Lockfile** — an npm `lockfileVersion` 3 file (`LOCKFILE_PATH`, default
`/app/data/package-lock.json`). Its `packages` object maps a node path to an
installed node:

- The empty-string key `""` is the root project, not an installed package.
- Every other key is a `node_modules/...`-nested path. The package name is the
  segment after the final `node_modules/`, and a scoped name keeps its
  `@scope/` prefix (for example `node_modules/a/node_modules/@s/b` is `@s/b`).
- A node carries its resolved `version`, an optional `dev` and `optional`
  boolean, and an optional `dependencies` object of name → semver range.

**Registry snapshot** — a JSON object (`REGISTRY_PATH`, default
`/app/data/registry.json`) mapping a package name to the array of published
version strings available for it. Upgrade targets are chosen only from this set.

**Advisory API** — an OSV-compatible service at `OSV_API_BASE` (default
`http://127.0.0.1:8730`). A `POST /v1/query` with body
`{"package":{"name":<name>,"ecosystem":"npm"}}` returns `{"vulns":[...]}`, each
entry an OSV record. Ranges are `SEMVER` type; a range's `events` list is a
sequence of `introduced` / `fixed` / `last_affected` boundaries forming affected
intervals. Severity is the string in `database_specific.severity`, one of `LOW`,
`MEDIUM`, `HIGH`, `CRITICAL`. Advisory identifiers are the `id` field. A local
mirror over the shipped advisories in `/app/vendor/osv` can be started with
`node /app/tools/osv-server.mjs`.

## Scope and requirements

A package is **in production scope** when at least one of its installed nodes is
neither a `dev` nor an `optional` dependency. Packages installed only as dev or
optional dependencies are ignored entirely and never appear in any artifact.

The **installed version** of a package is the `version` of its shallowest node
(fewest path segments; ties broken by the code-point-smaller path). The
**requirement ranges** for a package are every distinct range that names it in a
`dependencies` object anywhere in the tree — including the root project's own
`dependencies` — collected across the whole `packages` map, not just the top
level.

Advisories are queried once per distinct in-scope package name.

## Version semantics

Versions compare by Semantic Versioning 2.0.0 precedence: numeric `major`,
`minor`, `patch`, then pre-release. A pre-release version is lower than its
associated release; pre-release identifiers compare numerically when both are
numeric and lexically otherwise; when all shared identifiers are equal the
longer identifier list is higher. Build metadata (`+...`) is ignored.

Requirement ranges use the npm range grammar: `||` unions of space-joined
comparator sets, where each comparator is one of `^`, `~`, a hyphen range
`a - b`, an x-range (`1.2.x`, `1.x`, `*`), an exact version, or an operator
comparator (`>=`, `>`, `<`, `<=`, `=`). Carets keep the left-most non-zero
component fixed (`^1.2.3` is `>=1.2.3 <2.0.0`, `^0.2.3` is `>=0.2.3 <0.3.0`,
`^0.0.3` is `>=0.0.3 <0.0.4`). Tildes allow patch-level changes (`~1.2.3` is
`>=1.2.3 <1.3.0`, `~1` is `>=1.0.0 <2.0.0`). A version carrying a pre-release tag
satisfies a comparator set only when some comparator in that set is itself a
pre-release with the same `major.minor.patch` tuple; consequently `*` and plain
release comparators never admit a pre-release version.

A version is affected by an advisory when it falls inside one of the advisory's
intervals for the package: at or above an `introduced` boundary (a boundary of
`0` means `0.0.0`) and, for that interval, below its `fixed` boundary or at/below
its `last_affected` boundary (an interval with neither remains open and affects
every version at or above its `introduced`). The version that clears a `fixed`
interval is that interval's `fixed` value. Only `SEMVER` ranges of an `affected`
block whose `package.name` is the queried package and whose `package.ecosystem`
is `npm` are considered; other range types, other packages or ecosystems, and
any advisory carrying a `withdrawn` field are ignored.

## Decision policy

For each in-scope package resolved to `name@installed`:

- **clean** — no advisory applies to the installed version. No action.
- **vulnerable_fixable** — at least one advisory applies, and the registry
  contains a version that is higher than the installed version, is affected by
  *none* of the package's advisories, and satisfies *every* requirement range.
  The package is upgraded to the **lowest** such version.
- **no_safe_version** — at least one advisory applies and a higher unaffected
  version exists, but no unaffected higher version satisfies every requirement
  range. The package is blocked.
- **no_fix** — at least one advisory applies and no higher version clears every
  advisory. The package is blocked.

`max_severity` is the highest severity across a package's applicable advisories,
or null when there are none. A clean or blocked package contributes no override.

## Output artifacts

All paths are relative to `OUTPUT_DIR` (default `/app/out`).

**Report** — `remediation-report.json`, canonical JSON: object keys sorted
recursively by Unicode code point, compact separators (`,` and `:` with no
spaces), and exactly one trailing newline. Top-level keys are `blocked` (JSON
array of blocked package names, sorted), `generated_by` (the JSON string
`"npmguard"`), `overrides` (a JSON object mapping each upgraded package to its
target version), `packages` (JSON array of findings, sorted by name), and
`report_version` (the JSON string `"1"`, not a number). Each `packages` entry
holds `advisories` (sorted id strings), `constraints` (the sorted distinct
requirement ranges), `decision` (`"upgrade"`, `"block"` or `"ok"`),
`installed_version` (string), `max_severity` (string or `null`), `name`
(string), `paths` (sorted node-path strings where the package is installed),
`reason` (string), and `target_version` (string or `null`).

The example below is shown indented for readability; the file itself is the
canonical (compact, recursively key-sorted, newline-terminated) form of the same
value. It fixes the exact JSON type of every field.

```json
{
  "blocked": ["evil-dep"],
  "generated_by": "npmguard",
  "overrides": { "left-pad": "1.3.0" },
  "packages": [
    {
      "advisories": ["OSV-EVIL-1"],
      "constraints": ["^1.0.0"],
      "decision": "block",
      "installed_version": "1.0.0",
      "max_severity": "MEDIUM",
      "name": "evil-dep",
      "paths": ["node_modules/evil-dep"],
      "reason": "no_fix",
      "target_version": null
    },
    {
      "advisories": ["OSV-LEFTPAD-1"],
      "constraints": ["^1.1.0", "^1.2.0"],
      "decision": "upgrade",
      "installed_version": "1.1.0",
      "max_severity": "HIGH",
      "name": "left-pad",
      "paths": ["node_modules/left-pad"],
      "reason": "vulnerable_fixable",
      "target_version": "1.3.0"
    }
  ],
  "report_version": "1"
}
```

**Overrides** — `overrides.json`, canonical JSON, a single object with one key
`overrides` whose value is the same map as the report's `overrides` (empty
object when nothing is upgraded).

**Block stanzas** — one file per blocked package at `blocks/<name>.deny`, with
any `/` in the name replaced by `__` (so `@acme/parser` becomes
`@acme__parser.deny`):

```
Package: <name>
Installed: <installed_version>
Reason: <reason>
Action: manual-review
```

**Audit note** — `remediation-audit.md`:

```
# npm dependency remediation audit

Packages audited: <n>
Upgraded: <u>
Blocked: <b>
Clean: <c>

## <name>

- Installed: <installed_version>
- Decision: <UPGRADE to <target> | BLOCKED (<reason>) | CLEAN>
- Advisories: <comma-separated ids, or "none">
- Constraints: <comma-separated ranges, or "none">
```

Packages appear in sorted order, one `##` section each, separated by a blank
line, with a trailing newline at end of file.

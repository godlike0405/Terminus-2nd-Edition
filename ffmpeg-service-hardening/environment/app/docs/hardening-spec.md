# FFmpeg service hardening — contract

`ffguard` reads the workstation's host-state inventory, checks each FFmpeg
transcode service against the OSV advisory API, and writes the configuration
artifacts that bring the host into a hardened state. This document is the
contract every run must satisfy.

## Inputs

**Host-state inventory** — a SQLite database (`HOST_STATE_DB`, default
`/app/data/host_state.db`) with three tables:

- `packages(name, version, ecosystem)` — `version` is a Debian version string;
  `ecosystem` is `Debian`.
- `binaries(path, package)` — an absolute executable path and the package that
  owns it. `package` is `NULL` when no dpkg package owns the file.
- `services(unit, exec_path, enabled)` — a systemd unit, the absolute path of
  the executable it runs, and `1`/`0` for enabled.

**Advisory API** — an OSV-compatible service at `OSV_API_BASE` (default
`http://127.0.0.1:8730`). A `POST /v1/query` with body
`{"package":{"name":<name>,"ecosystem":"Debian"}}` returns `{"vulns":[...]}`,
every entry an OSV record. Ranges are `ECOSYSTEM` type over Debian versions; a
range's `events` list is a sequence of `introduced` / `fixed` / `last_affected`
boundaries forming affected intervals. Severity is the string in
`database_specific.severity`, one of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
Advisory identifiers are the `id` field. A local mirror of this API over the
shipped advisories in `/app/vendor/osv` can be started with
`node /app/tools/osv-server.mjs`.

## Scope and resolution

A service is in scope when the basename of its `exec_path` is `ffmpeg` or
`ffprobe`; all other units are ignored. For an in-scope service the installed
version is resolved `exec_path` → `binaries.package` → `packages.version`. A
service whose executable has no `binaries` row, whose owning package is `NULL`,
or whose owning package is absent from `packages` has no resolvable version;
for such a service both `package` and `installed_version` are reported as `null`
(the name from `binaries` is not carried through) and the decision is
`unverifiable`.

Advisories are queried once per distinct resolved package.

## Version semantics

All version comparisons — advisory range containment and pin-target selection —
use Debian version ordering (the `dpkg` algorithm: integer epochs, then upstream
and revision compared component-wise, with `~` sorting before everything and
numeric runs compared as integers).

A version is affected by an advisory when it falls inside one of the advisory's
intervals for the package: at or above an `introduced` boundary and, for that
interval, below its `fixed` boundary or at/below its `last_affected` boundary
(an interval with neither remains open and affects every version at or above its
`introduced`). The version that clears a `fixed` interval is that interval's
`fixed` value.

Only `ECOSYSTEM` ranges belonging to an `affected` block whose `package.name` is
the queried package and whose `package.ecosystem` is `Debian` are considered.
Other range types (for example `SEMVER` or `GIT`) and `affected` blocks for any
other package or ecosystem are ignored, and an advisory that carries a
`withdrawn` field is ignored in full.

## Decision policy

For each in-scope service:

- **unverifiable** — no resolvable version. The service is blocked.
- **clean** — a resolvable version with no applicable advisory. No action.
- **no_fix** — at least one applicable advisory whose containing interval has no
  fixed version. The service is blocked.
- **vulnerable_fixable** — every applicable advisory is fixable. The pin target
  is the highest (Debian ordering) of the applicable advisories' fixed versions.
  The service is pinned to that target.
- **no_safe_version** — every applicable advisory is fixable, but the pin target
  is itself affected by some advisory for the package. The service is blocked.

`max_severity` is the highest severity across a service's applicable advisories,
or null when there are none. A blocked or compliant service pins nothing.

## Output artifacts

All paths are relative to `OUTPUT_DIR` (default `/app/out`).

**APT pins** — one file per pinned package (packages, not services; when several
services pin the same package the highest target wins), at
`apt/preferences.d/ffguard-<package>.pref`:

```
Package: <package>
Pin: version <target>
Pin-Priority: 1001
```

**systemd overrides** — one drop-in per blocked unit, at
`systemd/system/<unit>.d/override.conf` (a templated unit such as
`transcode@.service` uses the directory `transcode@.service.d`):

```
[Service]
ExecStart=
ExecStart=/bin/false
NoNewPrivileges=yes
ProtectSystem=strict
```

**Report** — `hardening-report.json`, canonical JSON: object keys sorted
recursively by Unicode code point, compact separators (`,` and `:` with no
spaces), and exactly one trailing newline. Top-level keys are `blocked_units`
(JSON array of unit strings, sorted), `generated_by` (the JSON string
`"ffguard"`), `pins` (JSON array of `{"package", "version"}` objects sorted by
package), `report_version` (the JSON string `"1"`, not a number), and `services`.
Each `services` entry is sorted by `unit` and holds `advisories` (JSON array of
sorted id strings), `decision` (`"pin"`, `"block"` or `"ok"`), `enabled` (JSON
boolean), `exec_path` (string), `installed_version` (string or `null`),
`max_severity` (string or `null`), `package` (string or `null`), `pin_version`
(string or `null`), `reason` (string), and `unit` (string).

The example below is shown indented for readability; the file itself is the
canonical (compact, recursively key-sorted, newline-terminated) form of the same
value. It fixes the exact JSON type of every field.

```json
{
  "blocked_units": ["preview.service"],
  "generated_by": "ffguard",
  "pins": [
    { "package": "ffmpeg", "version": "7:5.1.6-0+deb12u1" }
  ],
  "report_version": "1",
  "services": [
    {
      "advisories": ["OSV-2024-1000"],
      "decision": "pin",
      "enabled": true,
      "exec_path": "/usr/bin/ffmpeg",
      "installed_version": "7:5.1.4-0+deb12u1",
      "max_severity": "CRITICAL",
      "package": "ffmpeg",
      "pin_version": "7:5.1.6-0+deb12u1",
      "reason": "vulnerable_fixable",
      "unit": "transcode@.service"
    },
    {
      "advisories": [],
      "decision": "block",
      "enabled": true,
      "exec_path": "/usr/local/bin/ffmpeg",
      "installed_version": null,
      "max_severity": null,
      "package": null,
      "pin_version": null,
      "reason": "unverifiable",
      "unit": "preview.service"
    }
  ]
}
```

**Audit note** — `ffmpeg-hardening-audit.md`:

```
# FFmpeg transcode hardening audit

Services scanned: <n>
Pinned: <p>
Blocked: <b>
Compliant: <c>

## <unit>

- Executable: <exec_path>
- Package: <package or "untracked">
- Installed version: <version or "unknown">
- Decision: <PINNED to <target> | BLOCKED (<reason>) | COMPLIANT>
- Advisories: <comma-separated ids, or "none">
```

Units appear in sorted order, one `##` section each, separated by a blank line,
with a trailing newline at end of file.

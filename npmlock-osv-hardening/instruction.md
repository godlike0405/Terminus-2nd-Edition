Our production Node service pins its whole dependency tree in a committed npm
lockfile, and the supply-chain gate that is supposed to keep that tree free of
known-vulnerable packages has gone quiet. The `npmguard` tool in `/app` is meant
to be that gate, but it was left half-migrated and the remediation plan it emits
can no longer be trusted — it under-reports vulnerable packages and writes its
output in the wrong shape.

`npmguard` reads the project's lockfile and an offline registry snapshot, checks
every production dependency against the OSV advisory API at `OSV_API_BASE`, and
for each package decides what to do: leave it alone when no advisory affects the
installed version, upgrade it to the lowest published version that clears every
advisory and still satisfies every version requirement the tree places on it, or
block it when no such safe upgrade exists — either because nothing higher escapes
the advisories or because the only unaffected releases would violate a dependent's
range. It then writes the machine-readable remediation report, the npm overrides
map, a quarantine stanza per blocked package, and a Markdown audit note.

Version precedence and requirement ranges follow Semantic Versioning and the npm
range grammar, advisory ranges follow OSV SEMVER interval semantics, and the exact
lockfile model, decision rules, and output paths and formats are specified in
`/app/docs/remediation-spec.md`. Make `npmguard` produce the correct artifacts for
whatever project snapshot and advisory data it is pointed at, and keep it runnable
as `/app/bin/npmguard`.

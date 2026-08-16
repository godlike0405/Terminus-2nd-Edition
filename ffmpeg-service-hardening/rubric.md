# Rubric 1
Agent runs the shipped ffguard tool and inspects its generated artifacts before editing code, +1
Agent reads /app/docs/hardening-spec.md before implementing the repairs, +1
Agent inspects the packages, binaries and services tables of the host-state database, +1
Agent implements Debian version comparison that parses epoch, upstream and revision components, +3
Agent orders tilde pre-release versions below their base version and compares digit runs as integers, +2
Agent implements queryOsv as an HTTP POST to the /v1/query endpoint carrying the package name and the Debian ecosystem, +3
Agent walks advisory event intervals (introduced/fixed, introduced/last_affected and open introduced) to decide containment, +3
Agent applies the Debian comparator to both range containment and pin-target selection, +2
Agent skips advisories that carry a withdrawn field when computing applicability, +2
Agent restricts containment to ECOSYSTEM ranges whose affected block names the queried package in the Debian ecosystem, +2
Agent resolves each service version through the exec_path to binaries.package to packages.version chain, +3
Agent maps every unresolvable executable to a null package, a null installed_version and a block decision, +2
Agent keeps only units whose executable basename is ffmpeg or ffprobe in scope, +1
Agent writes APT pins at apt/preferences.d/ffguard-<package>.pref and systemd drop-ins at systemd/system/<unit>.d/override.conf under the output directory, +2
Agent rebuilds the TypeScript so /app/dist reflects the edited sources, +2
Agent verifies the repaired tool end to end against a locally served advisory mirror before finishing, +3
Agent hardcodes advisory contents or decision outcomes into the tool, -5
Agent ships a final version comparator based on plain string or dot-split numeric ordering, -3
Agent edits the shipped host inventory or vendor advisory fixtures to force outcomes, -3
Agent finishes with TypeScript sources that fail to compile, -3
Agent introduces timestamps, randomness or other nondeterminism into the generated artifacts, -2

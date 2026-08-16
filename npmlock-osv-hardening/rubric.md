# Rubric 1
Agent runs the shipped npmguard tool and inspects its generated artifacts before editing code, +1
Agent reads /app/docs/remediation-spec.md before implementing the repairs, +1
Agent inspects the lockfile packages map, the registry snapshot and the advisory fixtures, +1
Agent implements Semantic Versioning precedence that orders pre-release versions below their associated release, +3
Agent compares numeric version identifiers as integers rather than as strings, +2
Agent implements npm range satisfaction for caret, tilde, hyphen and x-range comparators, +3
Agent applies the zero-major caret rule so that a caret on 0.2.x stays within the 0.2 line, +2
Agent excludes pre-release versions from ranges that carry no matching pre-release comparator, +2
Agent implements queryOsv as an HTTP POST to the /v1/query endpoint carrying the package name and the npm ecosystem, +3
Agent walks advisory event intervals covering introduced/fixed, introduced/last_affected and open introduced boundaries, +3
Agent restricts containment to SEMVER ranges naming the queried package in the npm ecosystem and skips withdrawn advisories, +2
Agent gathers requirement ranges from every node in the tree, including non-root nodes, +3
Agent selects the lowest registry version that clears every advisory and satisfies every requirement range as the upgrade target, +3
Agent distinguishes the no_fix and no_safe_version block reasons when no safe upgrade exists, +2
Agent excludes dev-only and optional-only packages from the audit scope, +1
Agent writes the canonical JSON report, the overrides map, the per-package block stanzas and the audit note at the specified output paths, +2
Agent verifies the repaired tool end to end against a locally served advisory mirror before finishing, +3
Agent hardcodes advisory contents or upgrade targets into the tool, -5
Agent ships a final version comparator based on plain string or dot-split numeric ordering, -3
Agent edits the shipped lockfile, registry snapshot or advisory fixtures to force outcomes, -3
Agent finishes with TypeScript sources that fail to compile, -3
Agent introduces timestamps, randomness or other nondeterminism into the generated artifacts, -2

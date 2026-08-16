Agent inspects the cartridge inventory and operations policy before changing host configuration, +2
Agent removes the rejected shared cartridge unit and replaces it with native template-based activation, +1
Agent derives each udev allowlist rule from both the cartridge UUID and hardware serial, +5
Agent derives per-profile device bindings and encrypted credential references from inventory, +5
Agent implements the serialized open-to-verification-to-mount-to-worker lifecycle, +5
Agent implements failure-tolerant unmount and cryptsetup cleanup for every service exit path, +5
Agent confines privileged setup and sheds all capabilities before executing the archive worker, +5
Agent derives aggregate slice controls and per-profile resource ceilings from inventory, +3
Agent implements profile-scoped failure quarantine with bounded retries and a hardened marker writer, +3
Agent configures the static service identity and every required directory with exact ownership and modes, +2
Agent enables exactly the inventory-defined cartridge instances through the shared template, +1
Agent validates the completed native configuration with systemd and the policy checker, +2
Agent successfully builds the binary at /app/bin/memory-reconcile with go build, +3
Agent verifies the implementation by running it against the provided sample data and inspecting output correctness, +2
Agent reads and understands the reconciliation contract document before attempting implementation, +2
Agent reads the existing stub main.go to understand what needs replacement, +1
Agent tests edge cases or error paths (invalid input, trailing JSON, relative paths, atomicity preservation), +2
Agent embeds credential contents in a unit, environment file, script, or other host configuration, -5
Agent leaves a wildcard udev rule that activates arbitrary LUKS devices, -5
Agent uses a destructive broad filesystem operation outside the named host-policy paths, -3
Agent weakens cleanup by ignoring the cartridge mapping identity or closing mappings globally, -3
Agent allows the archive worker to inherit CAP_SYS_ADMIN or equivalent mount authority, -5
Agent quarantines all cartridges or a different profile when one instance fails, -5




Agent implements strict JSON parsing that rejects unknown fields and trailing JSON values, +3
Agent implements input validation covering identifier regex, acyclic parent graph, connected hierarchy, acyclic reclaim dependencies, and numeric constraints, +3
Agent implements the hierarchical integer allocation algorithm with floor-division proportional weight distribution and remainder-byte distribution in ascending unit order, +5
Agent implements reclaim-wave scheduling with correct ordering (descending priority, descending reclaim bytes, ascending unit), parallelism cap, IO-domain exclusion, and dependency readiness, +5
Agent generates canonical compact JSON with lexicographically sorted keys and a single trailing newline, +3
Agent generates systemd conf files with exact format: [Slice] header, MemoryAccounting=yes, MemoryLow=LOW, MemoryHigh=HIGH, final newline, +2
Agent implements atomic output replacement that preserves existing output on any validation or computation error, +3
Agent enforces absolute-path requirement for all three flags (--inventory, --policy, --output), +1Agent inspects the cartridge inventory and operations policy before changing host configuration, +2
Agent removes the rejected shared cartridge unit and replaces it with native template-based activation, +1
Agent derives each udev allowlist rule from both the cartridge UUID and hardware serial, +5
Agent introduces code that does not compile or leaves dead code/globals that break correctness, -3
Agent fails to handle the reserve-exceeds-host-memory validation causing incorrect allocations, -2
Agent implements allocation algorithm incorrectly (wrong floor-division base, wrong remainder order, or cap spillover across hierarchy levels), -5
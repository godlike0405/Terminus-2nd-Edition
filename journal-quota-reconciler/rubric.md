Agent runs the shipped journal-reconcile command and inspects its artifacts before editing code, +1
Agent reads /app/docs/reconciliation-contract.md before implementing the repair, +1
Agent inspects both shipped inventory and policy inputs to understand shared-filesystem constraints, +1
Agent validates identifiers cross-references pool membership numeric bounds policy completeness both levels of aggregate floor feasibility and the complete acyclic dependency graph before writing output, +3
Agent computes each filesystem allocatable total from its budget capacity and reserve, +2
Agent allocates filesystem capacity among pools using capped weighted max-min allocation and deterministic integer remainder assignment, +5
Agent independently allocates every pool among its namespaces using the pool allocation as a hard boundary, +5
Agent accounts for pool-level unused capacity without spilling it into another pool, +2
Agent schedules dependency-ready vacuum actions into deterministic waves respecting priority age parallelism and shared I/O-domain exclusion, +5
Agent derives reclaim targets and byte counts from actual usage and computed allocations, +2
Agent escapes namespace names byte-wise using systemd filename escaping, +2
Agent writes every journald configuration with its computed allocation and filesystem reserve, +2
Agent emits recursively key-sorted compact plan JSON with deterministic array order and one trailing newline, +3
Agent replaces the requested output as one complete tree and preserves prior output on validation failure, +3
Agent rebuilds /app/bin/journal-reconcile from the repaired Go sources, +2
Agent exercises the repaired command end to end with local inputs before finishing, +1
Agent hardcodes allocations vacuum actions or shipped fixture outputs, -5
Agent edits the shipped inventory policy or contract to force a passing result, -3
Agent uses floating-point allocation or map iteration in a way that makes either allocation level nondeterministic, -3
Agent transfers unused namespace capacity across pool boundaries, -3
Agent ignores vacuum dependencies or schedules conflicting I/O domains in the same wave, -5
Agent writes into the final output before input validation completes, -3
Agent leaves stale artifacts from a previous reconciliation in the output tree, -2
Agent leaves Go sources uncompilable or fails to rebuild the installed executable, -3

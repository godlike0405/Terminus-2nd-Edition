# Task Explanation — Reconcile Journald Quotas Across Shared Filesystems

_Category: System Administration. This reviewer-facing file remains at the task root and is not copied into the agent environment._

## Difficulty Explanation

The task models a fleet controller that turns filesystem inventory and hierarchical storage policy into deployable journald limits and an operator vacuum plan. Its failures are operationally serious: independently reasonable per-namespace limits can overcommit shared storage, while redistributing unused capacity across an audit or tenant pool boundary violates isolation guarantees. Naive proportional allocation also mishandles caps and integer remainder, and unstable ordering can vacuum a lower-priority journal first. The shipped command produces plausible artifacts while ignoring almost all policy coupling.

The strengthened task requires two nested constrained allocations. Filesystem capacity is distributed among pools, then each pool is independently distributed among its namespaces; caps at either level create different forms of unused capacity and namespace-level slack must never spill across a pool boundary. Final allocations then feed a second algorithmic phase: validate an acyclic vacuum dependency graph and greedily construct parallel waves without placing two actions from a shared I/O domain together or unlocking a dependent within its predecessor's wave. A complete repair also requires systemd-compatible byte escaping, canonical nested serialization, and transactional filesystem replacement. These concerns compound, so an implementation with a correct allocator but an ordinary sort—or a correct scheduler over incorrect targets—still fails.

The task targets the Hard band through domain reasoning and coupled multi-stage reconciliation rather than numerous unrelated edge cases. Dynamic fixtures change names, topology, pool membership, weights, caps, priorities, and usage, preventing an answer specialized to the visible sample. Actual frontier-model difficulty remains empirical and must be established through platform runs.

## Solution Explanation

The Oracle parses both documents with strict typed structures and validates the complete hierarchy and dependency graph before creating output. It checks pool membership, proves that pool floors fit the filesystem while namespace floors fit their assigned pool, and rejects duplicate, missing, self-referential, or cyclic vacuum dependencies. It derives usable budget after the reserve and applies one generic integer weighted max-min procedure first to pools and then separately to the namespaces of each pool. Capped items leave their active set, integral leftovers go to active names in lexical order, and unused pool assignments remain isolated.

After deriving vacuum targets, the Oracle repeatedly freezes the dependency-ready set, orders it by operational priority, and greedily fills a wave subject to global parallelism and I/O-domain exclusion. Only completed prior waves satisfy dependencies. It then serializes the nested allocation and scheduled actions through maps so Go's JSON encoder emits lexically sorted keys.

Output is assembled in a sibling temporary directory. Only after all files are successfully written does the implementation exchange the old tree for the new one, with rollback on the final rename failure. The solution script installs the repaired source, formats it, and rebuilds the offline binary.

## Verification Explanation

The verifier treats the tool as a black box. An independent Python implementation computes both allocation levels, pool accounting, dependency-aware waves, configurations, and canonical bytes. Fresh cases exercise caps and remainders at both levels, UTF-8 escaping, fully capped capacity, and a load-bearing isolation case where one pool's namespace slack must not transfer to a hungry peer pool. A three-filesystem fixture forces the scheduler to distinguish dependency readiness from priority and global parallelism from shared-device exclusion. Invalid cross-reference, infeasible-hierarchy, and cyclic-graph cases confirm failure cannot modify or create output. The last check recompiles the source offline, ensuring the installed behavioral repair is backed by valid Go code. The original implementation fails the end-to-end cases; the Oracle is expected to pass all checks.

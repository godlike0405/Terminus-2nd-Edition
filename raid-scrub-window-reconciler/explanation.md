# Task Explanation — Reconcile RAID Scrubs Into Safe Maintenance Windows

_Category: System Administration. This reviewer-facing file remains at the task root and is not copied into the agent environment._

## Difficulty Explanation

The task models a storage controller that turns RAID inventory and maintenance policy into deployable systemd timer overrides. Its failures are operationally consequential: independently choosing the first available time for every array can overload a rack power feed, run two scrubs through one SAS controller, or start a dependent consistency pass before its prerequisite completes. The shipped JavaScript emits plausible plan data while omitting the coupled constraints and transactional behavior.

The strengthened repair requires deterministic resource-constrained scheduling rather than a collection of independent filters. Due jobs form a dependency DAG, but only due predecessors participate in runtime ordering, and each edge can impose a different post-completion gap. Existing maintenance reservations seed all resource ledgers but are not emitted as new jobs. At each step the implementation must choose by deadline, priority, and Unicode name, then find a contiguous interval bounded by earliest time and deadline.

Every candidate slot simultaneously participates in blackout, global concurrency, controller occupancy, and instantaneous per-domain watt accounting. In addition, each domain has a rolling energy limit: accepting one interval changes the watt-slot sum of every full window it intersects. A placement that looks safe slot by slot can therefore be illegal because of work several slots earlier, including a reservation on another controller. The selected placement then drives canonical JSON and byte-escaped systemd paths, and the full tree must replace old state transactionally.

The task targets the Hard band through these interacting scheduling invariants and operational filesystem guarantees. Dynamic fixtures vary graph shape, edge gaps, reservations, durations, deadlines, priorities, controller topology, power and energy limits, blackouts, and Unicode identifiers, so partial repairs and shipped-fixture specialization fail. Actual Hard status remains empirical and must be confirmed by valid frontier-model runs; infrastructure failures must not be counted as model failures.

## Solution Explanation

The Oracle parses strict flags and validates both documents before constructing output. It proves identifier and policy completeness, checks array and reservation bounds, and traverses the full graph—including disabled and recent arrays—to reject cycles. It derives the due set from enabled state and cadence. For each scheduling iteration it freezes the dependency-ready set, applies the specified deadline/priority/name ordering, and scans candidate starts from the maximum of the job's earliest slot and every due predecessor's end plus edge gap.

Slot-indexed ledgers track blackout membership, total concurrent work, each controller's occupancy, and watts per power domain. Reservations populate those ledgers first and are rejected if they already conflict. A candidate is accepted only when every occupied slot satisfies the ordinary resources and every complete rolling window remains within its domain's watt-slot budget. Committing a job updates all ledgers and derives Unix times from the window epoch and slot length.

The solution sorts jobs by start and name, recursively sorts JSON object keys, and escapes timer unit paths from UTF-8 bytes. It writes the entire tree under a sibling temporary directory, moves an existing tree aside only after all temporary writes succeed, installs the new tree with one rename, and rolls the old tree back if that final rename fails.

## Verification Explanation

The verifier is black-box and uses an independent Python scheduler to compute the complete plan and timer files. The shipped fleet case covers dependency gaps, reservations, shared power and rolling-energy domains, blackouts, disabled arrays, recent arrays, and Unicode escaping. Fresh fixtures separate controller locks from rack power and global concurrency, force an instantaneously safe job later solely because of a rolling watt-slot window, make deadline/priority/lexical selection load-bearing, and alter names and epochs to deter hard-coding.

Failure cases prove that an infeasible contiguous placement and conflicting committed reservations preserve existing markers, cycles among disabled arrays are still invalid, unknown references and incomplete policies create no output, and relative paths are rejected. A success case starts with stale content and an empty due set to ensure whole-tree replacement. The final check executes Node's parser against the installed source and confirms the command retains failing CLI behavior when required flags are absent.

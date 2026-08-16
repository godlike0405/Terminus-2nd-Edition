Agent reads /app/docs/scheduling-contract.md before implementing the repair, +1
Agent inspects both shipped inventory and policy inputs to identify shared maintenance constraints, +1
Agent validates CLI paths document structure identifiers references reservation bounds policy completeness and the full acyclic dependency graph before output mutation, +2
Agent selects due jobs from enabled state last scrub day cadence and the policy day, +2
Agent repeatedly selects dependency-ready jobs by deadline priority and array name, +3
Agent delays every dependent job until each due predecessor has completed and its configured gap has elapsed, +5
Agent searches for the earliest contiguous placement within each job's earliest and deadline bounds, +3
Agent excludes every blackout slot from scheduled intervals, +2
Agent seeds resource ledgers from reservations and enforces global parallelism and controller exclusivity for every occupied slot, +5
Agent independently enforces instantaneous watts and every rolling watt-slot budget in each power domain, +5
Agent derives slot and Unix start and end values from the selected placement and window parameters, +2
Agent escapes timer unit names byte-wise and emits exact deterministic systemd timer drop-ins only for due jobs, +3
Agent emits recursively key-sorted compact plan JSON with stable job ordering and one trailing newline, +2
Agent replaces the requested output as one complete tree and preserves prior output on every failure, +3
Agent exercises the repaired command end to end with local inputs before finishing, +1
Agent hardcodes the shipped schedule timestamps or timer artifacts, -5
Agent edits the shipped inventory policy or scheduling contract to force a passing result, -3
Agent treats dependencies as start ordering without waiting for predecessor completion, -5
Agent omits reservations from controller concurrency or power ledgers, -5
Agent checks instantaneous power but ignores rolling energy windows, -5
Agent schedules through blackout slots or past a job deadline, -3
Agent writes into the requested output before validation and scheduling complete, -3
Agent leaves stale artifacts from an earlier reconciliation in the output tree, -2
Agent leaves the JavaScript source invalid or the installed command disconnected from the repair, -3

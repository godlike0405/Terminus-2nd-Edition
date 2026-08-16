# RAID scrub maintenance scheduling contract

`scrub-window` reconciles array state and maintenance policy into a collision-free set of systemd timer drop-ins. It is an offline planning command:

```
scrub-window --inventory /absolute/inventory.json --policy /absolute/policy.json --output /absolute/output
```

Unknown or missing flags, non-absolute paths, malformed input, an infeasible schedule, or any rule violation must exit nonzero. Diagnostics go to stderr.

## Input model and validation

Both documents are JSON objects. Unknown fields are allowed. All listed numeric fields are safe non-negative integers unless a stricter bound is stated.

The inventory has:

- `window_start_unix`: the Unix second represented by slot zero.
- `controllers`: a nonempty array of `{id, power_domain}` with unique nonempty strings.
- `arrays`: an array of `{name, controller, timer_unit, enabled, last_scrub_day, duration_slots, earliest_slot, deadline_slot, load_watts, scrub_after}`. Names and timer units are unique nonempty strings; `controller` exists; booleans are booleans; `duration_slots` and `load_watts` are positive. `scrub_after` is an array of `{array, gap_slots}` objects with unique `array` values other than the containing array; `gap_slots` is non-negative.
- `reservations`: an array of `{id, controller, start_slot, end_slot, load_watts}` describing maintenance already committed inside this horizon. IDs are unique nonempty strings, controllers exist, load is positive, and each interval satisfies `0 <= start_slot < end_slot <= horizon_slots`.

The policy has:

- `today_day`: the current integral day number.
- `slot_minutes`: a positive integer.
- `horizon_slots`: a positive integer.
- `max_parallel`: a positive integer.
- `power_limits`: an object containing every inventory power domain exactly once, with positive integer watt limits.
- `energy_limits`: an object containing every inventory power domain exactly once. Each value is `{window_slots, max_watt_slots}` with positive integers and `window_slots <= horizon_slots`.
- `blackouts`: an array of `[start_slot, end_slot]` half-open intervals satisfying `0 <= start < end <= horizon_slots`. Intervals may overlap.
- `arrays`: an object containing every inventory array exactly once. Each value is `{cadence_days, priority}` where `cadence_days` is positive and `priority` is an integer.

Every array reference in `scrub_after` must exist, and the complete dependency graph must be acyclic, including disabled and not-due arrays. Each array must satisfy `earliest_slot < deadline_slot <= horizon_slots` and `duration_slots <= deadline_slot - earliest_slot`.

Reservations seed the resource ledgers before due jobs are placed. They may occupy blackout slots, but reservations themselves must not overlap on one controller, exceed `max_parallel`, exceed their power domain's instantaneous limit, or violate its rolling energy limit. For a domain with window length `W`, every full horizon window `[s, s+W)` for `0 <= s <= horizon_slots-W` must contain at most `max_watt_slots` total watt-slots: sum each running reservation or job's `load_watts` once per occupied slot. Invalid committed reservations make the input invalid.

## Due jobs and placement

An array is due exactly when it is enabled and `today_day - last_scrub_day >= cadence_days`. Dependencies control ordering only among due jobs; a dependency that is disabled or not due is already satisfied and contributes no gap.

Schedule due jobs one at a time. At each step, form the ready set whose due dependencies have already been scheduled. Select the ready job by earliest `deadline_slot`, then greater policy `priority`, then UTF-8 array name in ascending code-point order.

Place the selected job at the earliest integer start slot at or after its `earliest_slot` and at or after `end_slot + gap_slots` for every due dependency. Its occupied half-open interval `[start_slot, end_slot)` must end no later than `deadline_slot`; contain no blackout slot; keep reservations plus due jobs at or below `max_parallel`; not overlap a reservation or job on the same controller; keep instantaneous watts in its controller's power domain at or below that domain's power limit in every slot; and preserve every full rolling energy window's watt-slot limit after the candidate is added. If no placement exists, the entire reconciliation fails.

## Output

Build a complete new tree without modifying the requested output until parsing, validation, scheduling, and all temporary writes succeed. On any failure, preserve an existing output byte-for-byte and do not create a missing output. On success, replace any old tree completely so no stale files remain.

Write `plan.json` as compact UTF-8 JSON with object keys recursively sorted in ascending code-point order and exactly one trailing newline. Its schema is:

```
{
  "horizon_slots": INTEGER,
  "slot_minutes": INTEGER,
  "window_start_unix": INTEGER,
  "jobs": [
    {
      "array": STRING,
      "controller": STRING,
      "power_domain": STRING,
      "timer_unit": STRING,
      "start_slot": INTEGER,
      "end_slot": INTEGER,
      "start_unix": INTEGER,
      "end_unix": INTEGER,
      "load_watts": INTEGER
    }
  ]
}
```

Sort `jobs` by `start_slot`, then `array`.

For every job, write `systemd/<escaped timer_unit>.d/scrub-window.conf`. Escape the timer unit byte-by-byte as UTF-8: ASCII letters, digits, `_`, and `.` remain literal; every other byte becomes lowercase `\xhh`. File content is exactly:

```
[Timer]
OnCalendar=
OnCalendar=@START_UNIX
AccuracySec=1s
RandomizedDelaySec=0
Persistent=false
```

with `START_UNIX` replaced by the computed value and one final newline. Do not emit a drop-in for a disabled or not-due array.

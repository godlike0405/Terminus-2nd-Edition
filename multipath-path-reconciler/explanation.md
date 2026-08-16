# Task Explanation — Remediate a Multipath SAN Host

_Category: System Administration. Reviewer-facing; this file remains outside the agent environment._

## Difficulty Explanation

This task is an OS-level storage remediation, not an application-development exercise. The agent inherits a host with conflicting multipath defaults, an over-broad path rule, stale persistent WWIDs, a disabled restart policy, permissive LVM discovery, incomplete early-boot modules, and no consumer ordering. It must reconcile device-mapper multipath, persistent WWID state, systemd daemon and mount dependencies, udev, tmpfiles, LVM, and initramfs policy.

The task targets Hard through coupled operational constraints. Strict discovery is ineffective if persistent WWID state admits an old LUN, and a correct daemon is insufficient if LVM races it for raw paths or mounts start before mapper devices. The two array families deliberately require incompatible profiles: active/active flash uses ALUA priority groups, service-time selection, immediate failback, and one timeout/scheduler pair, while the active/passive vault uses failover groups, constant priority, round-robin selection, manual failback, and different device tuning. Solvers must isolate those profiles while reasoning about first-match LVM filters, initramfs module retention, systemd escaping, and required versus optional storage.

## Solution Explanation

The Oracle replaces the global multipath policy with strict discovery, a deny-by-default device blacklist, explicit exceptions for the approved inventory, one independently derived profile per array, and stable per-LUN aliases. It rewrites the persistent WWID file with private permissions so discovery state and configuration agree.

For lifecycle management, it installs a drop-in that orders after and wants network readiness, clears inherited pre-start commands, validates the multipath configuration, applies bounded restart behavior, and enables the packaged unit through the expected sysinit target link. It installs separate vendor/model-scoped udev rules so each array receives its own timeout and scheduler together, adds a root-owned tmpfiles declaration, and removes all named obsolete fragments.

The Oracle also replaces the permissive LVM filter with ordered accept rules for stable maps followed by raw-path and catch-all rejects while preserving discard behavior. It retains the existing NVMe initramfs module, adds the complete multipath stack, applies a private initramfs umask, and generates strong device/service dependencies for the required database mount but weak non-binding dependencies for the optional archive mount. Finally, it validates native configuration with installed tools.

## Verification Explanation

The verifier parses the multipath block structure independently and compares semantic directives rather than requiring the Oracle’s whitespace. It derives WWIDs, aliases, both complete array profiles, and device tuning from the shipped inventory, verifies the deny/allow relationship and profile isolation, checks the absence of kernel path names, and confirms persistent records and permissions.

Separate tests inspect repeated systemd directives, the vendor-unit enablement symlink, the narrow single-line udev match, tmpfiles semantics, and removal of every obsolete fragment. Additional tests derive stable aliases and mount roles from inventory, exercise LVM filter order, ensure early-boot module completeness without losing NVMe, and distinguish required mount binding from optional weak ordering. A final black-box invocation of `multipath -t` confirms that the installed tool accepts and expands the finished configuration. The checks exercise native host configuration and do not inspect the agent’s command history or implementation method.

# Task Explanation — Reconcile Encrypted Backup Cartridge Host Policy

_Category: System Administration. Reviewer-facing and not copied into the image._

## Difficulty Explanation

This is direct Linux host administration across udev, systemd, sysusers,
tmpfiles, cryptsetup, filesystem mounting, and logrotate. A plausible wildcard
udev rule is already present, but it trusts any LUKS volume and starts a shared
unit. The replacement must turn the supplied hardware inventory into an exact
two-factor device allowlist and a coherent template deployment.

The difficult parts are coupled. The udev UUID and serial must select the same
profile whose drop-in binds the corresponding device unit; the credential,
mapping name, expected inner filesystem UUID, mount options, runtime ceiling,
and I/O weight must remain attached to that profile. A shared lock must cover
the destructive lifecycle rather than only cryptsetup. Cleanup must attempt
both unmount and close after any failure without broadening the mapping target.
A locally reasonable configuration can therefore be unsafe even when every
individual command looks familiar. The prompt states the tested unit interface
and lifecycle syntax explicitly; difficulty remains in deriving and assembling
the complete cross-file host policy correctly rather than guessing hidden
format requirements.

The strengthened version adds a real privilege transition. Cryptsetup and
mount need `CAP_SYS_ADMIN`, but the long-running worker must not inherit it, so
the setup shell is narrowly bounded and the worker is launched through
`setpriv` with every capability set emptied. That must coexist with a private
mount namespace, strict filesystem visibility, syscall and address-family
filters, inventory-derived per-profile ceilings, and an aggregate accounting
slice. Misplacing any control can either break setup or leave the worker with
host mount authority.

The new quarantine path adds a state transition across units rather than
another static sandbox list. A failed `%i` instance must create exactly its own
operator-readable marker through a separately constrained oneshot; that marker
must block only the same profile on future udev activation. Restart windows and
burst thresholds come from different inventory levels, so global quarantine,
unbounded retries, or a marker path that drops `%i` are unsafe despite otherwise
valid cartridge configuration.

## Solution Explanation

The Oracle reads `/app/bin/cartridge-inventory`, creates the static service and
operator groups, and declares the state, runtime, mount, and log directories.
It emits one exact-match udev rule and one service drop-in per inventory row,
then enables those instances through a common template.

The template takes the shared lock, opens the profile's LUKS mapping using a
systemd encrypted credential, verifies the mapped filesystem UUID before
mounting, applies the exact mount options, and drops all remaining capabilities
through `setpriv` before invoking the archive worker. The shared template
provides the namespace and filesystem confinement; the aggregate slice and
profile drop-ins apply their respective inventory-derived resource budgets.
Two independent failure-tolerant cleanup commands lazily unmount the profile
path and close only that profile's mapping. The main unit routes failures to a
minimal quarantine template, whose narrowly bounded install command writes the
profile marker after cleanup.

## Verification Explanation

The verifier independently loads the inventory and parses the native files. It
checks the exact identity and directory declarations, rejects wildcard,
UUID-only, or incorrectly ordered activation rules, validates every profile's device-unit binding and
credential path and four named drop-in assignments, confirms the template's named inventory environment mapping,
source mount dependency, journal directives, lifecycle ordering, and worker
arguments, and checks that enabled instances exactly match the inventory. It also checks the setup
sandbox, capability-shedding boundary, aggregate slice, per-profile limits,
retry budgets, failure routing, and quarantine writer, including that blocking
state retains `%i` and cannot quarantine unrelated profiles. It scans host
configuration as bytes for credential leakage, validates log rotation, invokes
`systemd-analyze verify`, and finally runs the shipped policy checker. The
rejected initial state lacks nearly every required artifact and fails, while
the deterministic Oracle is intended to pass from a clean image.

# SAN host remediation runbook

The host uses Debian device-mapper multipath. Apply the configuration directly
under `/etc`; do not replace `multipath`, `multipathd`, `systemctl`, or `udevadm`.

## Multipath policy

`/etc/multipath.conf` must contain one `defaults` block with:

- `find_multipaths strict`
- `user_friendly_names no`
- `polling_interval 5`
- `no_path_retry queue`
- `queue_without_daemon no`
- `flush_on_last_del yes`

Use a `blacklist` block with `devnode ".*"` and a `blacklist_exceptions` block
containing exactly the inventory WWIDs. Configure exactly one `device` entry
per inventory array. Copy that array's `vendor`, `product`,
`pathGroupingPolicy`, `pathSelector`, `prio`, `pathChecker`, `failback`, and
`features` values to the corresponding multipath directives; every entry also
uses `retain_attached_hw_handler yes`. Array profiles must not inherit one
another's failback or selection behavior.

Create one `multipath` entry per inventory LUN. Each entry contains only its
`wwid` and stable inventory `alias`. Do not place credentials or individual
kernel path names in multipath configuration.

`/etc/multipath/wwids` must use the standard `/WWID/` record form, contain
exactly the three inventory WWIDs once each in inventory order, and be mode
0600.

## Daemon lifecycle

Replace managed drop-ins with
`/etc/systemd/system/multipathd.service.d/10-san-readiness.conf`. Its `[Unit]`
section must contain `Wants=network-online.target` and
`After=network-online.target`; use the weak `Wants=` dependency here, not
`Requires=`. Its `[Service]` section must clear `ExecStartPre`, then run
`/sbin/multipath -t` as the sole pre-start check, use `Restart=on-failure`, and
`RestartSec=5s`. Put `StartLimitIntervalSec=60s` and `StartLimitBurst=3` in
`[Unit]`.

Enable the vendor `multipathd.service` at sysinit by creating
`/etc/systemd/system/sysinit.target.wants/multipathd.service` as a symlink to
`/lib/systemd/system/multipathd.service`. Do not create a replacement unit.

## Device and runtime policy

Install exactly one managed rule per inventory array as
`/etc/udev/rules.d/60-<array-name>-san-paths.rules`. Each must react to `add`
and `change`, restrict matches to `SUBSYSTEM=="block"` and
`ENV{DEVTYPE}=="disk"`, match only that array's vendor and product, and set its
inventory `timeout` and `scheduler` values together in the same rule.

Install `/etc/tmpfiles.d/multipath-runtime.conf` with exactly one rule that
creates `/run/multipath` as a root-owned directory with mode 0755.

Remove these obsolete managed fragments:

- `/etc/multipath/conf.d/90-legacy-san.conf`
- `/etc/udev/rules.d/90-legacy-timeouts.rules`
- `/etc/systemd/system/multipathd.service.d/legacy-multipath.conf`

Validate syntax with `multipath -t`, use `systemd-analyze verify` for the vendor
unit plus drop-in, and ask `udevadm verify` to check the installed udev rule.

## Early boot, LVM, and mount consumers

The host must never let LVM claim an individual SCSI path behind multipath.
Keep `issue_discards = 1` in the `devices` block of `/etc/lvm/lvm.conf`, remove
the permissive legacy `filter`, and set `global_filter` in this exact decision
order:

1. accept each inventory `/dev/mapper/<alias>` in LUN order;
2. reject raw paths matching `/dev/sd[a-z]+`;
3. reject everything else.

Use anchored LVM regexes. Each rule must be a separate list item so first-match
semantics are visible.

Replace the legacy initramfs fragment with
`/etc/initramfs-tools/conf.d/multipath-host`, containing `MULTIPATH=y` and
`UMASK=0077`. `/etc/initramfs-tools/modules` must retain the existing `nvme`
entry and contain exactly one entry each for `dm_multipath`, `dm_round_robin`,
and `scsi_dh_alua`. Remove
`/etc/initramfs-tools/conf.d/legacy-root.conf`.

For each inventory `mountUnit`, install
`/etc/systemd/system/<mountUnit>.d/20-san-device.conf`. Derive the mapper device
unit from the alias using systemd escaping (`-` becomes `\x2d`), for example
`db-ledger` becomes `dev-mapper-db\x2dledger.device`.

Both drop-ins put `After=multipathd.service <escaped-device-unit>` in `[Unit]`.
For an inventory LUN with `availability: required`, also put both names in
`Requires=` and put the escaped device unit in `BindsTo=`. For
`availability: optional`, put both names in `Wants=` and do not add
`Requires=` or `BindsTo=`.

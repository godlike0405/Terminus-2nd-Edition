# Archive cartridge operations policy

`cartridge-inventory` is the authoritative snapshot. Profiles and identifiers
use only ASCII letters, digits, and hyphens. The host accepts a block device
only when `ID_FS_TYPE=crypto_LUKS`, both its filesystem UUID and serial match
one inventory row, and that row's service instance is enabled.

The static account owns `/var/lib/archive-cartridge` and
`/run/archive-cartridge`; operators in group `archive-operators` may inspect
logs. Runtime mounts live below `/run/archive-cartridge/mnt/<profile>`.

An instance is tied to `/dev/disk/by-uuid/<luksUuid>` and must stop when that
device disappears. It loads credential `luks.key` from the row's encrypted
credential path, takes the shared archive lock, opens the row's mapping with
cryptsetup in LUKS mode, verifies that the mapping contains the expected
filesystem UUID, mounts it with exactly the row's options, and invokes the
worker as:

The per-profile drop-in exposes those values as
`DEVICE=/dev/disk/by-uuid/<luksUuid>`, `MAPPING=<mapping>`,
`FILESYSTEM_UUID=<filesystemUuid>`, and `MOUNT_OPTIONS=<mountOptions joined by
commas>`.

`archive-cartridge-worker --profile <profile> --source /srv/archive/source --destination <mountpoint> --state /var/lib/archive-cartridge/<profile>.json`

Use systemd start/stop limits of 90 seconds and the row's
`maxRuntimeSeconds`, `IOWeight`, `Nice=10`, `UMask=0077`, journal logging with
identifier `archive-cartridge-<profile>`, and no automatic restart. In the
template this means `StandardOutput=journal`, `StandardError=journal`, and
`SyslogIdentifier=archive-cartridge-%i`. The template declares
`RequiresMountsFor=/srv/archive/source` and maps the inventory into
`PROFILE=%i`, `SOURCE=<source>`, `STATE_DIR=<stateDirectory>`,
`MOUNT_ROOT=<mountRoot>`, `LOCK_FILE=<lock>`, and `WORKER=<worker>`
environment assignments. Cleanup
must lazily unmount the profile mount and close only its mapping, with failures
ignored so every cleanup action is attempted.

All instances belong to `/etc/systemd/system/archive-cartridge.slice`. Enable
CPU, memory, task, and I/O accounting there and apply the inventory slice's
`CPUQuota`, binary-megabyte `MemoryMax`, and `TasksMax`. Each instance applies
its row's binary-megabyte `MemoryMax` and byte-exact `LimitFSIZE`.

The setup process keeps only `CAP_SYS_ADMIN`, uses a private mount namespace
and network namespace, and restricts address families to `AF_UNIX`. Set
`NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
`ProtectControlGroups=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`,
`RestrictSUIDSGID=yes`, `SystemCallArchitectures=native`,
`SystemCallFilter=@system-service @mount`, and
`SystemCallErrorNumber=EPERM`. The source is read-only; only the state
directory, mount root, and `/run/archive-cartridge` are writable. After
mounting, start the worker through `setpriv` with empty bounding, inheritable,
and ambient capability sets plus no-new-privileges, so the worker cannot
inherit mount authority.

Failure containment is profile-scoped. The main template uses the inventory
`failureWindowSeconds`, each instance uses its row's `failureBurst`, and any
failed instance triggers `archive-cartridge-quarantine@<profile>.service` with
job mode `replace-irreversibly`. A profile cannot start while
`/var/lib/archive-cartridge/quarantine/<profile>.blocked` exists.

The quarantine template is a root oneshot with `UMask=0027`,
`NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, only the quarantine directory writable, and a capability
bounding set containing exactly `CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER`. It
uses `/usr/bin/install` to atomically create an empty `0640` marker owned by
`archive-cartridge:archive-operators`. Operators clear a marker manually only
after investigating that cartridge.

The account has a nologin shell. Tmpfiles creates the state and runtime
directories `0750`, mount root `0710`, quarantine directory `0750`, and log
directory `0750`; quarantine and logs use group `archive-operators`, while
other paths use the service group. Rotate `*.log` weekly for 12 compressed
copies using `copytruncate` and `missingok`; skip empty logs with `notifempty`,
and create replacements with mode `0640`, owner `archive-cartridge`, and group
`archive-operators`.

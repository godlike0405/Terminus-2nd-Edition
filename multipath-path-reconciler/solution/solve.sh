#!/bin/bash
set -euo pipefail

root="${SAN_HOST_ROOT:-}"
install -d -m 0755 "$root/etc/multipath" "$root/etc/multipath/conf.d"
install -d -m 0755 "$root/etc/systemd/system/multipathd.service.d"
install -d -m 0755 "$root/etc/systemd/system/sysinit.target.wants"
install -d -m 0755 "$root/etc/udev/rules.d" "$root/etc/tmpfiles.d"
install -d -m 0755 "$root/etc/lvm" "$root/etc/initramfs-tools/conf.d"
install -d -m 0755 "$root/etc/systemd/system/db-ledger.mount.d"
install -d -m 0755 "$root/etc/systemd/system/queue-archive.mount.d"
install -d -m 0755 "$root/etc/systemd/system/audit-vault.mount.d"

cat > "$root/etc/multipath.conf" <<'EOF'
defaults {
    find_multipaths strict
    user_friendly_names no
    polling_interval 5
    no_path_retry queue
    queue_without_daemon no
    flush_on_last_del yes
}

blacklist {
    devnode ".*"
}

blacklist_exceptions {
    wwid "3600508b400105e210000900000490000"
    wwid "3600508b400105e210000900000490099"
    wwid "3600a098038314c6d2f5d4f524f553741"
}

devices {
    device {
        vendor "ACME"
        product "FlashArray"
        path_grouping_policy group_by_prio
        path_selector "service-time 0"
        prio alua
        path_checker tur
        failback immediate
        features "1 queue_if_no_path"
        retain_attached_hw_handler yes
    }
    device {
        vendor "NIMBUS"
        product "VaultDisk"
        path_grouping_policy failover
        path_selector "round-robin 0"
        prio const
        path_checker tur
        failback manual
        features "0"
        retain_attached_hw_handler yes
    }
}

multipaths {
    multipath {
        wwid "3600508b400105e210000900000490000"
        alias "db-ledger"
    }
    multipath {
        wwid "3600508b400105e210000900000490099"
        alias "queue-archive"
    }
    multipath {
        wwid "3600a098038314c6d2f5d4f524f553741"
        alias "audit-vault"
    }
}
EOF

cat > "$root/etc/multipath/wwids" <<'EOF'
# Multipath wwids, Version : 1.0
/3600508b400105e210000900000490000/
/3600508b400105e210000900000490099/
/3600a098038314c6d2f5d4f524f553741/
EOF
chmod 0600 "$root/etc/multipath/wwids"

cat > "$root/etc/systemd/system/multipathd.service.d/10-san-readiness.conf" <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
ExecStartPre=
ExecStartPre=/sbin/multipath -t
Restart=on-failure
RestartSec=5s
EOF

cat > "$root/etc/udev/rules.d/60-flash-san-paths.rules" <<'EOF'
ACTION=="add|change", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ATTRS{vendor}=="ACME", ATTRS{model}=="FlashArray", ATTR{device/timeout}="30", ATTR{queue/scheduler}="none"
EOF

cat > "$root/etc/udev/rules.d/60-vault-san-paths.rules" <<'EOF'
ACTION=="add|change", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ATTRS{vendor}=="NIMBUS", ATTRS{model}=="VaultDisk", ATTR{device/timeout}="60", ATTR{queue/scheduler}="mq-deadline"
EOF

cat > "$root/etc/tmpfiles.d/multipath-runtime.conf" <<'EOF'
d /run/multipath 0755 root root -
EOF

cat > "$root/etc/lvm/lvm.conf" <<'EOF'
devices {
    issue_discards = 1
    global_filter = [ "a|^/dev/mapper/db-ledger$|", "a|^/dev/mapper/queue-archive$|", "a|^/dev/mapper/audit-vault$|", "r|^/dev/sd[a-z]+$|", "r|.*|" ]
}
EOF

cat > "$root/etc/initramfs-tools/conf.d/multipath-host" <<'EOF'
MULTIPATH=y
UMASK=0077
EOF

cat > "$root/etc/initramfs-tools/modules" <<'EOF'
# Existing boot-storage driver
nvme
dm_multipath
dm_round_robin
scsi_dh_alua
EOF

cat > "$root/etc/systemd/system/db-ledger.mount.d/20-san-device.conf" <<'EOF'
[Unit]
Requires=multipathd.service dev-mapper-db\x2dledger.device
After=multipathd.service dev-mapper-db\x2dledger.device
BindsTo=dev-mapper-db\x2dledger.device
EOF

cat > "$root/etc/systemd/system/queue-archive.mount.d/20-san-device.conf" <<'EOF'
[Unit]
Wants=multipathd.service dev-mapper-queue\x2darchive.device
After=multipathd.service dev-mapper-queue\x2darchive.device
EOF

cat > "$root/etc/systemd/system/audit-vault.mount.d/20-san-device.conf" <<'EOF'
[Unit]
Requires=multipathd.service dev-mapper-audit\x2dvault.device
After=multipathd.service dev-mapper-audit\x2dvault.device
BindsTo=dev-mapper-audit\x2dvault.device
EOF

rm -f \
    "$root/etc/multipath/conf.d/90-legacy-san.conf" \
    "$root/etc/udev/rules.d/90-legacy-timeouts.rules" \
    "$root/etc/systemd/system/multipathd.service.d/legacy-multipath.conf" \
    "$root/etc/initramfs-tools/conf.d/legacy-root.conf"
ln -sfn /lib/systemd/system/multipathd.service \
    "$root/etc/systemd/system/sysinit.target.wants/multipathd.service"

if [ -z "$root" ]; then
    multipath -t >/dev/null
    systemd-analyze verify /lib/systemd/system/multipathd.service
    systemd-analyze verify /etc/systemd/system/db-ledger.mount
    systemd-analyze verify /etc/systemd/system/queue-archive.mount
    systemd-analyze verify /etc/systemd/system/audit-vault.mount
    udevadm verify /etc/udev/rules.d/60-flash-san-paths.rules
    udevadm verify /etc/udev/rules.d/60-vault-san-paths.rules
fi

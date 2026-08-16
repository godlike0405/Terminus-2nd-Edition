#!/bin/sh
set -eu

root=${HOST_ROOT:-}
app_dir=${APP_DIR:-/app}
inventory=$(mktemp)
trap 'rm -f "$inventory"' EXIT
"$app_dir/bin/cartridge-inventory" > "$inventory"

node_get() {
    node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));let v=d;for(const p of process.argv[2].split("."))v=v[p];process.stdout.write(Array.isArray(v)?v.join(","):String(v))' "$inventory" "$1"
}

account=$(node_get account)
group=$(node_get group)
worker=$(node_get worker)
source_dir=$(node_get source)
lock_file=$(node_get lock)
state_dir=$(node_get stateDirectory)
mount_root=$(node_get mountRoot)
quarantine_dir=$(node_get quarantineDirectory)
failure_window=$(node_get failureWindowSeconds)
log_dir=$(node_get logDirectory)
slice_cpu=$(node_get slice.cpuQuotaPercent)
slice_memory=$(node_get slice.memoryMiB)
slice_tasks=$(node_get slice.tasksMax)

install -d -m 0755 \
    "$root/etc/systemd/system" "$root/etc/sysusers.d" "$root/etc/tmpfiles.d" \
    "$root/etc/udev/rules.d" "$root/etc/logrotate.d"
rm -f "$root/etc/systemd/system/archive-cartridge.service"

cat > "$root/etc/sysusers.d/archive-cartridge.conf" <<EOF
g archive-operators -
g $group -
u $account - "Archive cartridge worker" $state_dir /usr/sbin/nologin
EOF

cat > "$root/etc/tmpfiles.d/archive-cartridge.conf" <<EOF
d $state_dir 0750 $account $group -
d /run/archive-cartridge 0750 $account $group -
d $mount_root 0710 $account $group -
d $quarantine_dir 0750 $account archive-operators -
d $log_dir 0750 $account archive-operators -
EOF

cat > "$root/etc/systemd/system/archive-cartridge@.service" <<EOF
[Unit]
Description=Encrypted archive cartridge %i
RequiresMountsFor=$source_dir
StartLimitIntervalSec=$failure_window
ConditionPathExists=!$quarantine_dir/%i.blocked
OnFailure=archive-cartridge-quarantine@%i.service
OnFailureJobMode=replace-irreversibly

[Service]
Type=exec
User=root
Group=root
UMask=0077
TimeoutStartSec=90
TimeoutStopSec=90
Nice=10
Restart=no
PrivateMounts=yes
PrivateNetwork=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @mount
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SYS_ADMIN
ReadOnlyPaths=$source_dir
ReadWritePaths=$state_dir $mount_root /run/archive-cartridge
StandardOutput=journal
StandardError=journal
SyslogIdentifier=archive-cartridge-%i
Environment=PROFILE=%i
Environment=SOURCE=$source_dir
Environment=STATE_DIR=$state_dir
Environment=MOUNT_ROOT=$mount_root
Environment=LOCK_FILE=$lock_file
Environment=WORKER=$worker
ExecStart=/bin/sh -ceu 'exec 9>"\${LOCK_FILE}"; /usr/bin/flock -x 9; /usr/sbin/cryptsetup open --type luks --key-file "\${CREDENTIALS_DIRECTORY}/luks.key" "\${DEVICE}" "\${MAPPING}"; test "\$(/usr/sbin/blkid -s UUID -o value "/dev/mapper/\${MAPPING}")" = "\${FILESYSTEM_UUID}"; /bin/mount -o "\${MOUNT_OPTIONS}" "/dev/mapper/\${MAPPING}" "\${MOUNT_ROOT}/\${PROFILE}"; exec /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs -- "\${WORKER}" --profile "\${PROFILE}" --source "\${SOURCE}" --destination "\${MOUNT_ROOT}/\${PROFILE}" --state "\${STATE_DIR}/\${PROFILE}.json"'
ExecStopPost=-/bin/umount -l \${MOUNT_ROOT}/\${PROFILE}
ExecStopPost=-/usr/sbin/cryptsetup close \${MAPPING}

[Install]
WantedBy=multi-user.target
EOF

cat > "$root/etc/systemd/system/archive-cartridge-quarantine@.service" <<EOF
[Unit]
Description=Quarantine failed archive cartridge %i

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
ReadWritePaths=$quarantine_dir
ExecStart=/usr/bin/install -m 0640 -o $account -g archive-operators /dev/null $quarantine_dir/%i.blocked
EOF

cat > "$root/etc/systemd/system/archive-cartridge.slice" <<EOF
[Unit]
Description=Encrypted archive cartridge resource budget

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
IOAccounting=yes
CPUQuota=$slice_cpu%
MemoryMax=${slice_memory}M
TasksMax=$slice_tasks
EOF

: > "$root/etc/udev/rules.d/70-archive-cartridge.rules"
install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"

count=$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(d.cartridges.length)' "$inventory")
i=0
while [ "$i" -lt "$count" ]; do
    row=$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(JSON.stringify(d.cartridges[Number(process.argv[2])]))' "$inventory" "$i")
    get_row() {
        node -e 'const d=JSON.parse(process.argv[1]);let v=d;for(const p of process.argv[2].split("."))v=v[p];process.stdout.write(Array.isArray(v)?v.join(","):String(v))' "$row" "$1"
    }
    profile=$(get_row profile)
    luks_uuid=$(get_row luksUuid)
    fs_uuid=$(get_row filesystemUuid)
    mapping=$(get_row mapping)
    credential=$(get_row credential)
    serial=$(get_row deviceSerial)
    mount_options=$(get_row mountOptions)
    max_runtime=$(get_row maxRuntimeSeconds)
    io_weight=$(get_row ioWeight)
    memory_max=$(get_row memoryMiB)
    max_archive_bytes=$(get_row maxArchiveBytes)
    failure_burst=$(get_row failureBurst)
    device="/dev/disk/by-uuid/$luks_uuid"
    device_unit=$(systemd-escape --path --suffix=device "$device")

    printf '%s\n' "SUBSYSTEM==\"block\", ENV{ID_FS_TYPE}==\"crypto_LUKS\", ENV{ID_FS_UUID}==\"$luks_uuid\", ENV{ID_SERIAL_SHORT}==\"$serial\", TAG+=\"systemd\", ENV{SYSTEMD_WANTS}+=\"archive-cartridge@$profile.service\"" >> "$root/etc/udev/rules.d/70-archive-cartridge.rules"

    dropin="$root/etc/systemd/system/archive-cartridge@$profile.service.d"
    install -d -m 0755 "$dropin"
    cat > "$dropin/10-cartridge.conf" <<EOF
[Unit]
BindsTo=$device_unit
After=$device_unit
StartLimitBurst=$failure_burst

[Service]
Environment=DEVICE=$device
Environment=MAPPING=$mapping
Environment=FILESYSTEM_UUID=$fs_uuid
Environment=MOUNT_OPTIONS=$mount_options
RuntimeMaxSec=$max_runtime
IOWeight=$io_weight
MemoryMax=${memory_max}M
LimitFSIZE=$max_archive_bytes
Slice=archive-cartridge.slice
LoadCredential=luks.key:$credential
EOF
    ln -sfn ../archive-cartridge@.service "$root/etc/systemd/system/multi-user.target.wants/archive-cartridge@$profile.service"
    i=$((i + 1))
done

cat > "$root/etc/logrotate.d/archive-cartridge" <<EOF
$log_dir/*.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    copytruncate
    create 0640 $account archive-operators
}
EOF

"$app_dir/bin/cartridge-policy-check" "${root:-/}"

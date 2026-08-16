"""Behavioral validation for the encrypted cartridge host policy."""

from __future__ import annotations

import configparser
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

ROOT = Path(os.environ.get("HOST_ROOT", "/"))
APP = Path(os.environ.get("APP_DIR", "/app"))
INVENTORY = json.loads((APP / "data/cartridges.json").read_text())


def host(path: str) -> Path:
    """Resolve an absolute path below the tested host root."""
    return ROOT / path.lstrip("/")


def read(path: str) -> str:
    """Read a required host policy file."""
    candidate = host(path)
    assert candidate.is_file(), f"missing {path}"
    return candidate.read_text()


def unit_text(profile: str | None = None) -> str:
    """Return the template or profile drop-in text."""
    if profile is None:
        return read("/etc/systemd/system/archive-cartridge@.service")
    return read(
        f"/etc/systemd/system/archive-cartridge@{profile}.service.d/10-cartridge.conf"
    )


def section(text: str, name: str) -> dict[str, str]:
    """Parse ordinary systemd assignments for one section."""
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read_string(text)
    return dict(parser[name])


def directives(text: str, name: str) -> list[str]:
    """Collect repeated systemd directives without collapsing them."""
    return [
        line.split("=", 1)[1]
        for line in text.splitlines()
        if line.strip().startswith(f"{name}=")
    ]


def environment_assignments(text: str) -> list[str]:
    """Parse equivalent quoted or unquoted systemd Environment assignments."""
    assignments: list[str] = []
    for value in directives(text, "Environment"):
        assignments.extend(shlex.split(value, comments=False, posix=True))
    return assignments


def test_rejected_legacy_unit_is_replaced_by_complete_native_policy() -> None:
    """The legacy daemon is absent and every required policy family exists."""
    assert not host("/etc/systemd/system/archive-cartridge.service").exists()
    required = [
        "/etc/sysusers.d/archive-cartridge.conf",
        "/etc/tmpfiles.d/archive-cartridge.conf",
        "/etc/udev/rules.d/70-archive-cartridge.rules",
        "/etc/systemd/system/archive-cartridge@.service",
        "/etc/systemd/system/archive-cartridge-quarantine@.service",
        "/etc/systemd/system/archive-cartridge.slice",
        "/etc/logrotate.d/archive-cartridge",
    ]
    assert all(host(path).is_file() for path in required)


def test_static_identity_and_directory_ownership_are_idempotent() -> None:
    """Sysusers and tmpfiles define exact identities, modes, and ownership."""
    sysusers = {
        tuple(line.split())
        for line in read("/etc/sysusers.d/archive-cartridge.conf").splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert ("g", "archive-operators", "-") in sysusers
    assert ("g", INVENTORY["group"], "-") in sysusers
    assert (
        "u",
        INVENTORY["account"],
        "-",
        '"Archive',
        "cartridge",
        'worker"',
        INVENTORY["stateDirectory"],
        "/usr/sbin/nologin",
    ) in sysusers
    tmpfiles = {
        tuple(line.split()[:6])
        for line in read("/etc/tmpfiles.d/archive-cartridge.conf").splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert tmpfiles == {
        (
            "d",
            INVENTORY["stateDirectory"],
            "0750",
            INVENTORY["account"],
            INVENTORY["group"],
            "-",
        ),
        (
            "d",
            "/run/archive-cartridge",
            "0750",
            INVENTORY["account"],
            INVENTORY["group"],
            "-",
        ),
        (
            "d",
            INVENTORY["mountRoot"],
            "0710",
            INVENTORY["account"],
            INVENTORY["group"],
            "-",
        ),
        (
            "d",
            INVENTORY["quarantineDirectory"],
            "0750",
            INVENTORY["account"],
            "archive-operators",
            "-",
        ),
        (
            "d",
            INVENTORY["logDirectory"],
            "0750",
            INVENTORY["account"],
            "archive-operators",
            "-",
        ),
    }


def test_udev_activation_is_an_exact_two_factor_allowlist() -> None:
    """Each rule uses the required audit order for its exact-match activation."""
    text = read("/etc/udev/rules.d/70-archive-cartridge.rules")
    rules = [line.strip() for line in text.splitlines() if line.strip()]
    assert len(rules) == len(INVENTORY["cartridges"])
    for row in INVENTORY["cartridges"]:
        matching = [line for line in rules if row["luksUuid"] in line]
        assert len(matching) == 1
        rule = matching[0]
        required_fields = [
            'SUBSYSTEM=="block"',
            'ENV{ID_FS_TYPE}=="crypto_LUKS"',
            f'ENV{{ID_FS_UUID}}=="{row["luksUuid"]}"',
            f'ENV{{ID_SERIAL_SHORT}}=="{row["deviceSerial"]}"',
            'TAG+="systemd"',
            f'ENV{{SYSTEMD_WANTS}}+="archive-cartridge@{row["profile"]}.service"',
        ]
        assert all(required in rule for required in required_fields)
        fields = rule.split(", ")
        positions = [
            next(index for index, field in enumerate(fields) if required in field)
            for required in required_fields
        ]
        assert positions == sorted(positions)
    assert "%E{" not in text and "*" not in text


def test_enabled_instances_match_inventory_and_template() -> None:
    """Exactly the discovered profiles are enabled through the shared template."""
    wants = host("/etc/systemd/system/multi-user.target.wants")
    links = list(wants.glob("archive-cartridge@*.service"))
    assert {link.name for link in links} == {
        f"archive-cartridge@{row['profile']}.service" for row in INVENTORY["cartridges"]
    }
    template = host("/etc/systemd/system/archive-cartridge@.service")
    assert all(link.is_symlink() and link.resolve() == template for link in links)


def test_profile_dropins_bind_devices_credentials_and_limits() -> None:
    """Every profile binds its device and derives credentials and resource limits."""
    for row in INVENTORY["cartridges"]:
        text = unit_text(row["profile"])
        unit = section(text, "Unit")
        service = section(text, "Service")
        device = f"/dev/disk/by-uuid/{row['luksUuid']}"
        escaped = subprocess.run(
            ["systemd-escape", "--path", "--suffix=device", device],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert unit["BindsTo"] == escaped
        assert unit["After"] == escaped
        assert unit["StartLimitBurst"] == str(row["failureBurst"])
        assert set(environment_assignments(text)) == {
            f"DEVICE={device}",
            f"MAPPING={row['mapping']}",
            f"FILESYSTEM_UUID={row['filesystemUuid']}",
            f"MOUNT_OPTIONS={','.join(row['mountOptions'])}",
        }
        assert service["LoadCredential"] == f"luks.key:{row['credential']}"
        assert service["RuntimeMaxSec"] == str(row["maxRuntimeSeconds"])
        assert service["IOWeight"] == str(row["ioWeight"])
        assert service["MemoryMax"] == f"{row['memoryMiB']}M"
        assert service["LimitFSIZE"] == str(row["maxArchiveBytes"])
        assert service["Slice"] == "archive-cartridge.slice"


def test_aggregate_slice_enforces_inventory_resource_budget() -> None:
    """The dedicated slice accounts and bounds all cartridge instances."""
    text = read("/etc/systemd/system/archive-cartridge.slice")
    values = section(text, "Slice")
    budget = INVENTORY["slice"]
    assert values == {
        "CPUAccounting": "yes",
        "MemoryAccounting": "yes",
        "TasksAccounting": "yes",
        "IOAccounting": "yes",
        "CPUQuota": f"{budget['cpuQuotaPercent']}%",
        "MemoryMax": f"{budget['memoryMiB']}M",
        "TasksMax": str(budget["tasksMax"]),
    }


def test_failure_state_is_scoped_to_the_triggering_profile() -> None:
    """The main template blocks and quarantines only the failed instance."""
    unit = section(unit_text(), "Unit")
    marker = f"{INVENTORY['quarantineDirectory']}/%i.blocked"
    assert unit["StartLimitIntervalSec"] == str(INVENTORY["failureWindowSeconds"])
    assert unit["ConditionPathExists"] == f"!{marker}"
    assert unit["OnFailure"] == "archive-cartridge-quarantine@%i.service"
    assert unit["OnFailureJobMode"] == "replace-irreversibly"
    assert "*" not in unit["ConditionPathExists"]
    assert "%i" in unit["ConditionPathExists"] and "%i" in unit["OnFailure"]


def test_quarantine_writer_is_minimal_hardened_and_operator_visible() -> None:
    """The quarantine oneshot creates one protected marker with narrow authority."""
    text = read("/etc/systemd/system/archive-cartridge-quarantine@.service")
    service = section(text, "Service")
    assert service["Type"] == "oneshot"
    assert service["User"] == "root"
    assert service["Group"] == "root"
    assert service["UMask"] == "0027"
    assert service["NoNewPrivileges"] == "yes"
    assert service["PrivateTmp"] == "yes"
    assert service["ProtectSystem"] == "strict"
    assert service["ProtectHome"] == "yes"
    assert service["CapabilityBoundingSet"] == ("CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER")
    assert service["ReadWritePaths"] == INVENTORY["quarantineDirectory"]
    assert service["ExecStart"] == (
        "/usr/bin/install -m 0640 "
        f"-o {INVENTORY['account']} -g archive-operators /dev/null "
        f"{INVENTORY['quarantineDirectory']}/%i.blocked"
    )


def test_privileged_setup_is_namespaced_and_filesystem_confined() -> None:
    """The setup keeps only mount authority inside narrow native sandboxes."""
    service = section(unit_text(), "Service")
    exact = {
        "PrivateMounts": "yes",
        "PrivateNetwork": "yes",
        "PrivateTmp": "yes",
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectControlGroups": "yes",
        "LockPersonality": "yes",
        "RestrictRealtime": "yes",
        "RestrictSUIDSGID": "yes",
        "SystemCallArchitectures": "native",
        "SystemCallFilter": "@system-service @mount",
        "SystemCallErrorNumber": "EPERM",
        "RestrictAddressFamilies": "AF_UNIX",
        "CapabilityBoundingSet": "CAP_SYS_ADMIN",
    }
    assert all(service[key] == value for key, value in exact.items())
    assert set(service["ReadOnlyPaths"].split()) == {INVENTORY["source"]}
    assert set(service["ReadWritePaths"].split()) == {
        INVENTORY["stateDirectory"],
        INVENTORY["mountRoot"],
        "/run/archive-cartridge",
    }


def test_template_lifecycle_serialization_and_worker_contract() -> None:
    """The lifecycle locks, opens, verifies, mounts, runs, and cleans in order."""
    text = unit_text()
    service = section(text, "Service")
    assert service["Type"] == "exec"
    assert service["TimeoutStartSec"] == "90"
    assert service["TimeoutStopSec"] == "90"
    assert service["Restart"] == "no"
    assert service["UMask"] == "0077"
    assert service["Nice"] == "10"
    command = service["ExecStart"]
    ordered = [
        "flock -x 9",
        "cryptsetup open --type luks",
        "blkid -s UUID -o value",
        "/bin/mount -o",
        "exec /usr/bin/setpriv --bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs --",
        '"${WORKER}" --profile "${PROFILE}"',
        '--source "${SOURCE}"',
        '--destination "${MOUNT_ROOT}/${PROFILE}"',
        '--state "${STATE_DIR}/${PROFILE}.json"',
    ]
    positions = [command.find(term) for term in ordered]
    assert all(position >= 0 for position in positions)
    assert positions == sorted(positions)
    assert '"${CREDENTIALS_DIRECTORY}/luks.key"' in command
    cleanup = directives(text, "ExecStopPost")
    assert cleanup == [
        "-/bin/umount -l ${MOUNT_ROOT}/${PROFILE}",
        "-/usr/sbin/cryptsetup close ${MAPPING}",
    ]


def test_template_uses_inventory_paths_and_journal_identity() -> None:
    """Common paths, source mount dependency, and logging are inventory-derived."""
    text = unit_text()
    unit = section(text, "Unit")
    service = section(text, "Service")
    assert unit["RequiresMountsFor"] == INVENTORY["source"]
    environments = set(environment_assignments(text))
    assert environments == {
        "PROFILE=%i",
        f"SOURCE={INVENTORY['source']}",
        f"STATE_DIR={INVENTORY['stateDirectory']}",
        f"MOUNT_ROOT={INVENTORY['mountRoot']}",
        f"LOCK_FILE={INVENTORY['lock']}",
        f"WORKER={INVENTORY['worker']}",
    }
    assert service["StandardOutput"] == "journal"
    assert service["StandardError"] == "journal"
    assert service["SyslogIdentifier"] == "archive-cartridge-%i"


def test_configuration_contains_no_credential_material() -> None:
    """Host policy refers to encrypted credential paths without embedding secrets."""
    markers = (b"BEGIN PRIVATE", b"LUKS_KEY=", b"cartridge-secret")
    leaked: list[Path] = []
    policy_roots = [
        host("/etc/systemd/system"),
        host("/etc/udev/rules.d"),
        host("/etc/sysusers.d"),
        host("/etc/tmpfiles.d"),
        host("/etc/logrotate.d"),
    ]
    for policy_root in policy_roots:
        for candidate in policy_root.rglob("*"):
            if candidate.is_file():
                data = candidate.read_bytes()
                if any(marker in data for marker in markers):
                    leaked.append(candidate)
    assert not leaked


def test_log_rotation_matches_archive_operations_policy() -> None:
    """Archive logs rotate weekly with exact retention, mode, and ownership."""
    text = read("/etc/logrotate.d/archive-cartridge")
    assert text.split("{", 1)[0].strip() == f"{INVENTORY['logDirectory']}/*.log"
    normalized = re.sub(r"\s+", " ", text)
    for term in (
        "weekly",
        "rotate 12",
        "compress",
        "missingok",
        "notifempty",
        "copytruncate",
        f"create 0640 {INVENTORY['account']} archive-operators",
    ):
        assert term in normalized


def test_native_tools_accept_the_completed_policy() -> None:
    """Systemd and the shipped policy checker accept the integrated result."""
    if ROOT == Path("/"):
        subprocess.run(
            [
                "systemd-analyze",
                "verify",
                "/etc/systemd/system/archive-cartridge.slice",
                "/etc/systemd/system/archive-cartridge@.service",
                "/etc/systemd/system/archive-cartridge-quarantine@.service",
                *[
                    f"/etc/systemd/system/archive-cartridge@{row['profile']}.service"
                    for row in INVENTORY["cartridges"]
                ],
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    result = subprocess.run(
        [str(APP / "bin/cartridge-policy-check"), str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "policy: ok"

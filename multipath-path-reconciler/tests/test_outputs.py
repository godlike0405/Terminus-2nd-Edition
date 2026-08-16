"""Behavioral verification of the remediated multipath host configuration."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(os.environ.get("SAN_TEST_ROOT", "/"))
INVENTORY = ROOT / "opt/san-host/inventory.json"
MULTIPATH = ROOT / "etc/multipath.conf"
WWIDS = ROOT / "etc/multipath/wwids"
DROPIN_DIR = ROOT / "etc/systemd/system/multipathd.service.d"
UDEV_DIR = ROOT / "etc/udev/rules.d"
TMPFILES = ROOT / "etc/tmpfiles.d/multipath-runtime.conf"
ENABLE_LINK = ROOT / "etc/systemd/system/sysinit.target.wants/multipathd.service"
LVM_CONFIG = ROOT / "etc/lvm/lvm.conf"
INITRAMFS_CONFIG = ROOT / "etc/initramfs-tools/conf.d/multipath-host"
INITRAMFS_MODULES = ROOT / "etc/initramfs-tools/modules"


def clean_lines(path: Path) -> list[str]:
    """Return non-empty, non-comment logical lines."""
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def parse_multipath(path: Path) -> list[dict[str, object]]:
    """Parse the block-and-directive subset used by multipath configuration."""
    roots: list[dict[str, object]] = []
    stack: list[list[dict[str, object]]] = [roots]
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "}":
            assert len(stack) > 1, f"unexpected closing brace on line {number}"
            stack.pop()
            continue
        if line.endswith("{"):
            name = line[:-1].strip()
            assert re.fullmatch(r"[a-z_]+", name), f"bad block on line {number}"
            children: list[dict[str, object]] = []
            stack[-1].append({"name": name, "children": children})
            stack.append(children)
            continue
        tokens = shlex.split(line, comments=False, posix=True)
        assert len(tokens) >= 2, f"bad directive on line {number}"
        stack[-1].append({"name": tokens[0], "value": " ".join(tokens[1:])})
    assert len(stack) == 1, "unclosed multipath block"
    return roots


def blocks(nodes: list[dict[str, object]], name: str) -> list[dict[str, object]]:
    """Select child blocks by name."""
    return [node for node in nodes if node.get("name") == name and "children" in node]


def directives(node: dict[str, object]) -> list[tuple[str, str]]:
    """Return the direct key/value directives in a parsed block."""
    children = node["children"]
    assert isinstance(children, list)
    return [
        (str(child["name"]), str(child["value"]))
        for child in children
        if "value" in child
    ]


@pytest.fixture
def inventory() -> dict[str, object]:
    """Load the approved host inventory used by the remediation."""
    return json.loads(INVENTORY.read_text())


@pytest.fixture
def config() -> list[dict[str, object]]:
    """Parse the installed multipath configuration."""
    assert MULTIPATH.is_file()
    return parse_multipath(MULTIPATH)


def test_defaults_enforce_strict_safe_daemon_behavior(config):
    """Defaults should use strict discovery and safe queue lifecycle behavior."""
    defaults = blocks(config, "defaults")
    assert len(defaults) == 1
    actual = directives(defaults[0])
    expected = {
        "find_multipaths": "strict",
        "user_friendly_names": "no",
        "polling_interval": "5",
        "no_path_retry": "queue",
        "queue_without_daemon": "no",
        "flush_on_last_del": "yes",
    }
    assert len(actual) == len(expected)
    assert dict(actual) == expected


def test_only_inventory_wwids_are_admitted(config, inventory):
    """A default deny policy should exempt exactly the approved LUN WWIDs."""
    deny = blocks(config, "blacklist")
    allow = blocks(config, "blacklist_exceptions")
    assert len(deny) == len(allow) == 1
    assert directives(deny[0]) == [("devnode", ".*")]
    expected = [("wwid", lun["wwid"]) for lun in inventory["luns"]]
    assert directives(allow[0]) == expected


def test_array_profiles_keep_distinct_failover_semantics(config, inventory):
    """Every approved array should retain its own complete path-selection profile."""
    devices = blocks(config, "devices")
    assert len(devices) == 1
    entries = blocks(devices[0]["children"], "device")
    assert len(entries) == len(inventory["arrays"])
    for entry, array in zip(entries, inventory["arrays"], strict=True):
        actual = directives(entry)
        expected = {
            "vendor": array["vendor"],
            "product": array["product"],
            "path_grouping_policy": array["pathGroupingPolicy"],
            "path_selector": array["pathSelector"],
            "prio": array["prio"],
            "path_checker": array["pathChecker"],
            "failback": array["failback"],
            "features": array["features"],
            "retain_attached_hw_handler": "yes",
        }
        assert len(actual) == len(expected)
        assert dict(actual) == expected


def test_luns_have_only_stable_inventory_aliases(config, inventory):
    """Every approved LUN should map once to its stable alias without path names."""
    groups = blocks(config, "multipaths")
    assert len(groups) == 1
    entries = blocks(groups[0]["children"], "multipath")
    actual = [directives(entry) for entry in entries]
    expected = [
        [("wwid", lun["wwid"]), ("alias", lun["alias"])] for lun in inventory["luns"]
    ]
    assert actual == expected
    assert not re.search(r"\bsd[a-z]+\b", MULTIPATH.read_text())


def test_wwid_state_is_exact_and_private(inventory):
    """Persistent WWID state should contain only approved records with mode 0600."""
    assert stat.S_IMODE(WWIDS.stat().st_mode) == 0o600
    records = clean_lines(WWIDS)
    assert records == [f"/{lun['wwid']}/" for lun in inventory["luns"]]


def parse_dropin(path: Path) -> dict[str, list[str]]:
    """Parse a systemd drop-in while retaining repeated directives."""
    result: dict[str, list[str]] = {}
    section = ""
    for line in clean_lines(path):
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        assert section and "=" in line
        key, value = line.split("=", 1)
        result.setdefault(f"{section}:{key}", []).append(value)
    return result


def test_systemd_dropin_validates_before_restart_and_service_is_enabled():
    """Systemd policy should validate configuration, restart safely, and enable boot."""
    dropins = sorted(path.name for path in DROPIN_DIR.iterdir() if path.is_file())
    assert dropins == ["10-san-readiness.conf"]
    values = parse_dropin(DROPIN_DIR / dropins[0])
    assert values == {
        "[Unit]:Wants": ["network-online.target"],
        "[Unit]:After": ["network-online.target"],
        "[Unit]:StartLimitIntervalSec": ["60s"],
        "[Unit]:StartLimitBurst": ["3"],
        "[Service]:ExecStartPre": ["", "/sbin/multipath -t"],
        "[Service]:Restart": ["on-failure"],
        "[Service]:RestartSec": ["5s"],
    }
    assert ENABLE_LINK.is_symlink()
    assert os.readlink(ENABLE_LINK) == "/lib/systemd/system/multipathd.service"


def test_udev_rules_are_array_scoped_and_keep_distinct_tuning(inventory):
    """Each array rule should narrowly match disks and apply its own path tuning."""
    expected_files = [
        f"60-{array['name']}-san-paths.rules" for array in inventory["arrays"]
    ]
    managed = sorted(path.name for path in UDEV_DIR.glob("60-*-san-paths.rules"))
    assert managed == sorted(expected_files)
    for array, filename in zip(inventory["arrays"], expected_files, strict=True):
        lines = clean_lines(UDEV_DIR / filename)
        assert len(lines) == 1
        fields = [field.strip() for field in lines[0].split(",")]
        assert set(fields) == {
            'ACTION=="add|change"',
            'SUBSYSTEM=="block"',
            'ENV{DEVTYPE}=="disk"',
            f'ATTRS{{vendor}}=="{array["vendor"]}"',
            f'ATTRS{{model}}=="{array["product"]}"',
            f'ATTR{{device/timeout}}="{array["timeout"]}"',
            f'ATTR{{queue/scheduler}}="{array["scheduler"]}"',
        }


def test_tmpfiles_rule_and_obsolete_fragments():
    """Runtime ownership should be declarative and obsolete fragments absent."""
    assert clean_lines(TMPFILES) == ["d /run/multipath 0755 root root -"]
    assert not (ROOT / "etc/multipath/conf.d/90-legacy-san.conf").exists()
    assert not (UDEV_DIR / "90-legacy-timeouts.rules").exists()
    assert not (DROPIN_DIR / "legacy-multipath.conf").exists()


def lvm_list_values(text: str, key: str) -> list[str]:
    """Extract one quoted LVM list without confusing regex brackets for its end."""
    assignment = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*\[", text)
    assert assignment, f"missing {key} list"
    start = assignment.end()
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character == "]":
            body = text[start:index]
            remainder = text[index + 1 :]
            assert not re.search(rf"(?m)^\s*{re.escape(key)}\s*=", remainder)
            return shlex.split(body.replace(",", " "))
    pytest.fail(f"unterminated {key} list")


def test_lvm_claims_only_stable_maps_and_preserves_discards(inventory):
    """LVM should accept stable maps first and reject raw paths and all fallbacks."""
    text = re.sub(r"#.*", "", LVM_CONFIG.read_text())
    assert len(re.findall(r"\bdevices\s*\{", text)) == 1
    assert re.findall(r"\bissue_discards\s*=\s*(\d+)", text) == ["1"]
    assert not re.search(r"(?m)^\s*filter\s*=", text)
    rules = lvm_list_values(text, "global_filter")
    aliases = [lun["alias"] for lun in inventory["luns"]]
    assert rules[:-1] == [
        *(f"a|^/dev/mapper/{alias}$|" for alias in aliases),
        r"r|^/dev/sd[a-z]+$|",
    ]
    assert rules[-1] in {"r|.*|", "r|^.*$|"}


def test_initramfs_is_private_and_contains_complete_storage_stack():
    """Early boot should retain NVMe and load each multipath module exactly once."""
    assert clean_lines(INITRAMFS_CONFIG) == ["MULTIPATH=y", "UMASK=0077"]
    assert not (ROOT / "etc/initramfs-tools/conf.d/legacy-root.conf").exists()
    modules = clean_lines(INITRAMFS_MODULES)
    assert modules == ["nvme", "dm_multipath", "dm_round_robin", "scsi_dh_alua"]
    assert len(modules) == len(set(modules))


def escaped_mapper_unit(alias: str) -> str:
    """Return the systemd device unit for an inventory mapper alias."""
    escaped = alias.replace("-", r"\x2d")
    return f"dev-mapper-{escaped}.device"


def test_mounts_use_role_appropriate_mapper_dependencies(inventory):
    """Required and optional mounts should use distinct strong and weak dependencies."""
    for lun in inventory["luns"]:
        unit = lun["mountUnit"]
        directory = ROOT / "etc/systemd/system" / f"{unit}.d"
        files = sorted(path.name for path in directory.iterdir() if path.is_file())
        assert files == ["20-san-device.conf"]
        values = parse_dropin(directory / files[0])
        device = escaped_mapper_unit(lun["alias"])
        ordered = f"multipathd.service {device}"
        if lun["availability"] == "required":
            assert values == {
                "[Unit]:Requires": [ordered],
                "[Unit]:After": [ordered],
                "[Unit]:BindsTo": [device],
            }
        else:
            assert lun["availability"] == "optional"
            assert values == {
                "[Unit]:Wants": [ordered],
                "[Unit]:After": [ordered],
            }


def test_installed_multipath_configuration_is_accepted():
    """The installed multipath parser should accept and expand the final policy."""
    if ROOT != Path("/"):
        pytest.skip("native parser check runs only inside the task container")
    completed = subprocess.run(
        ["/sbin/multipath", "-t"],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = completed.stdout
    assert "db-ledger" in rendered
    assert "queue-archive" in rendered
    assert "audit-vault" in rendered
    assert "group_by_prio" in rendered
    assert "failover" in rendered

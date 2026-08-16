"""Black-box verifier for the ffguard host-hardening tool.

The verifier never imports the tool. It mints its own SQLite host-state
inventories and OSV advisory sets, serves the advisories from a mock that
records what was queried, runs the compiled command, and compares every
produced artifact against an independent Python oracle. Deterministically
generated hosts make fixture-specific or hard-coded solutions insufficient.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import shutil
import signal
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest

import ffhard_kit as kit

APP = Path(os.environ.get("APP_DIR", "/app"))
CLI = ["node", str(APP / "dist" / "cli.js")]


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
def _run_tool(db_path: Path, osv_base: str, out_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOST_STATE_DB"] = str(db_path)
    env["OSV_API_BASE"] = osv_base
    env["OUTPUT_DIR"] = str(out_dir)
    return subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=60)


def _collect(out_dir: Path) -> dict[str, bytes]:
    produced: dict[str, bytes] = {}
    for path in out_dir.rglob("*"):
        if path.is_file():
            produced[str(path.relative_to(out_dir)).replace(os.sep, "/")] = path.read_bytes()
    return produced


class Case:
    """A single tool invocation with its expected artifacts and query log."""

    def __init__(self, produced, expected, queried, rows):
        self.produced = produced
        self.expected = expected
        self.queried = queried
        self.rows = rows

    def decision(self, unit: str) -> dict:
        return next(row for row in self.rows if row["unit"] == unit)


def run_case(base: Path, packages, binaries, services, advisories) -> Case:
    """Write the inventory, serve advisories, run the tool, and gather results."""
    base.mkdir(parents=True, exist_ok=True)
    db_path = base / "host_state.db"
    out_dir = base / "out"
    kit.write_db(str(db_path), packages, binaries, services)
    expected = kit.build_oracle(str(db_path), advisories)
    rows = kit.service_rows(str(db_path), advisories)
    with kit.OsvServer(advisories) as server:
        result = _run_tool(db_path, f"http://127.0.0.1:{server.port}", out_dir)
        # Keep every query, including any duplicates, so a tool that hits the API
        # more than once for the same package is detectable (the contract requires
        # exactly one query per distinct resolved package).
        queried = sorted(server.queried)
    assert result.returncode == 0, f"tool failed: {result.stdout}\n{result.stderr}"
    return Case(_collect(out_dir), expected, queried, rows)


def assert_artifacts_match(produced: dict[str, bytes], expected: dict[str, bytes]) -> None:
    """Compare artifacts to the oracle: exact file set and paths, byte-exact
    canonical JSON, and parsed (content and order, not byte-layout) comparison
    for the APT, systemd and Markdown text artifacts."""
    assert set(produced) == set(expected), (
        f"file set mismatch; missing={sorted(set(expected) - set(produced))} "
        f"extra={sorted(set(produced) - set(expected))}"
    )
    for name, data in expected.items():
        got = produced[name]
        if name.endswith(".json"):
            assert got == data, f"canonical JSON differs for {name}"
        elif name.endswith(".pref"):
            assert kit.parse_pref(got.decode("utf-8")) == kit.parse_pref(data.decode("utf-8")), (
                f"APT preferences fields differ for {name}"
            )
        elif name.endswith("override.conf"):
            assert kit.parse_override(got.decode("utf-8")) == kit.parse_override(data.decode("utf-8")), (
                f"systemd drop-in directives differ for {name}"
            )
        elif name.endswith(".md"):
            assert kit.parse_audit_md(got.decode("utf-8")) == kit.parse_audit_md(data.decode("utf-8")), (
                f"audit note content differs for {name}"
            )
        else:
            assert got == data, f"bytes differ for {name}"


def assert_parity(case: Case) -> None:
    assert_artifacts_match(case.produced, case.expected)


def adv(vid: str, pkg: str, events: list[dict], severity: str = "HIGH") -> dict:
    return {
        "id": vid,
        "affected": [{"package": {"name": pkg, "ecosystem": "Debian"},
                      "ranges": [{"type": "ECOSYSTEM", "events": events}]}],
        "database_specific": {"severity": severity},
    }


@pytest.fixture(scope="session", autouse=True)
def _built_tool() -> None:
    """The compiled entry point must exist before any case runs."""
    assert (APP / "dist" / "cli.js").is_file(), f"missing compiled tool at {APP / 'dist' / 'cli.js'}"


# --------------------------------------------------------------------------- #
# Scope and resolution
# --------------------------------------------------------------------------- #
def test_only_ffmpeg_tool_services_are_in_scope(tmp_path: Path) -> None:
    """Only units whose executable basename is ffmpeg or ffprobe are audited."""
    packages = [("ffmpeg", "7:5.1.4-1", "Debian"), ("nginx", "1.22.1-9", "Debian")]
    binaries = [
        ("/usr/bin/ffmpeg", "ffmpeg"),
        ("/usr/bin/ffmpeg-helper", "ffmpeg"),
        ("/usr/sbin/nginx", "nginx"),
    ]
    services = [
        ("transcode.service", "/usr/bin/ffmpeg", 1),
        ("helper.service", "/usr/bin/ffmpeg-helper", 1),
        ("web.service", "/usr/sbin/nginx", 1),
    ]
    case = run_case(tmp_path, packages, binaries, services, {"ffmpeg": []})
    units = [row["unit"] for row in case.rows]
    assert units == ["transcode.service"]
    assert_parity(case)


def test_unresolvable_binaries_are_blocked_unverifiable(tmp_path: Path) -> None:
    """A missing binaries row, a NULL package, or an unknown package blocks the unit."""
    packages = [("ffmpeg", "7:5.1.4-1", "Debian")]
    binaries = [
        ("/usr/local/bin/ffmpeg", None),        # untracked
        ("/opt/x/ffmpeg", "ghost-package"),      # package absent from packages
        # /missing/ffmpeg has no binaries row at all
    ]
    services = [
        ("untracked.service", "/usr/local/bin/ffmpeg", 1),
        ("ghost.service", "/opt/x/ffmpeg", 1),
        ("missing.service", "/missing/ffmpeg", 0),
    ]
    case = run_case(tmp_path, packages, binaries, services, {"ffmpeg": []})
    for unit in ("untracked.service", "ghost.service", "missing.service"):
        row = case.decision(unit)
        assert row["decision"] == "block" and row["reason"] == "unverifiable"
        assert row["package"] is None and row["installed_version"] is None
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Version semantics
# --------------------------------------------------------------------------- #
def test_debian_version_ordering_drives_decisions(tmp_path: Path) -> None:
    """Tilde pre-releases and Debian revisions must compare by dpkg rules, not string/numeric splits."""
    packages = [
        ("ff-rc", "5.1.4~rc2-1", "Debian"),     # pre-release below the fixed release
        ("ff-rev", "5.1.4-1", "Debian"),         # older revision than the fix
    ]
    binaries = [("/srv/a/ffmpeg", "ff-rc"), ("/srv/b/ffmpeg", "ff-rev")]
    services = [("rc.service", "/srv/a/ffmpeg", 1), ("rev.service", "/srv/b/ffmpeg", 1)]
    advisories = {
        "ff-rc": [adv("OSV-RC", "ff-rc", [{"introduced": "5.1"}, {"fixed": "5.1.4-1"}], "HIGH")],
        "ff-rev": [adv("OSV-REV", "ff-rev", [{"introduced": "5.1"}, {"fixed": "5.1.4-2"}], "MEDIUM")],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    assert case.decision("rc.service")["decision"] == "pin"
    assert case.decision("rc.service")["pin_version"] == "5.1.4-1"
    assert case.decision("rev.service")["decision"] == "pin"
    assert case.decision("rev.service")["pin_version"] == "5.1.4-2"
    assert_parity(case)


def test_epoch_dominates_upstream_in_containment(tmp_path: Path) -> None:
    """An epoch makes a version outrank any epoch-0 boundary regardless of upstream digits."""
    packages = [("ff-epoch", "1:2.0.0-1", "Debian")]
    binaries = [("/srv/e/ffmpeg", "ff-epoch")]
    services = [("epoch.service", "/srv/e/ffmpeg", 1)]
    advisories = {"ff-epoch": [adv("OSV-EPOCH", "ff-epoch", [{"introduced": "5.0"}], "HIGH")]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    row = case.decision("epoch.service")
    assert row["decision"] == "block" and row["reason"] == "no_fix"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Range containment
# --------------------------------------------------------------------------- #
def test_multi_interval_reintroduction_is_contained_correctly(tmp_path: Path) -> None:
    """A version in the second interval of a reintroduced advisory is fixable to that interval's fix."""
    packages = [("ff-multi", "7:6.1.0-1", "Debian")]
    binaries = [("/srv/m/ffmpeg", "ff-multi")]
    services = [("multi.service", "/srv/m/ffmpeg", 1)]
    events = [{"introduced": "0"}, {"fixed": "5.0"}, {"introduced": "6.1"}, {"fixed": "7:6.1.3-1"}]
    advisories = {"ff-multi": [adv("OSV-MULTI", "ff-multi", events, "HIGH")]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    row = case.decision("multi.service")
    assert row["decision"] == "pin" and row["pin_version"] == "7:6.1.3-1"
    assert_parity(case)


def test_last_affected_and_open_ranges_have_no_fix(tmp_path: Path) -> None:
    """last_affected and open (no fixed) intervals are unpatched and block the unit."""
    packages = [("ff-last", "7:5.1.1-1", "Debian"), ("ff-open", "7:4.4.0-1", "Debian")]
    binaries = [("/srv/l/ffmpeg", "ff-last"), ("/srv/o/ffmpeg", "ff-open")]
    services = [("last.service", "/srv/l/ffmpeg", 1), ("open.service", "/srv/o/ffmpeg", 1)]
    advisories = {
        "ff-last": [adv("OSV-LAST", "ff-last", [{"introduced": "5.1"}, {"last_affected": "7:5.1.2-1"}])],
        "ff-open": [adv("OSV-OPEN", "ff-open", [{"introduced": "4.0"}])],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    assert case.decision("last.service")["reason"] == "no_fix"
    assert case.decision("open.service")["reason"] == "no_fix"
    assert_parity(case)


def test_withdrawn_advisories_are_ignored(tmp_path: Path) -> None:
    """An advisory carrying a withdrawn field must not influence any decision."""
    packages = [("ff-w", "7:5.1.4-1", "Debian")]
    binaries = [("/w/ffmpeg", "ff-w")]
    services = [("w.service", "/w/ffmpeg", 1)]
    live = adv("OSV-LIVE", "ff-w", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}], "HIGH")
    dead = adv("OSV-DEAD", "ff-w", [{"introduced": "5.1"}, {"fixed": "7:5.1.9-1"}], "CRITICAL")
    dead["withdrawn"] = "2026-01-01T00:00:00Z"
    case = run_case(tmp_path, packages, binaries, services, {"ff-w": [live, dead]})
    row = case.decision("w.service")
    assert row["decision"] == "pin" and row["pin_version"] == "7:5.1.6-1"
    assert row["advisories"] == ["OSV-LIVE"]
    assert row["max_severity"] == "HIGH"
    assert_parity(case)


def test_non_ecosystem_ranges_and_foreign_blocks_are_ignored(tmp_path: Path) -> None:
    """Only ECOSYSTEM ranges for the Debian package count; decoy ranges and blocks are skipped."""
    packages = [("ff-d", "7:5.1.4-1", "Debian")]
    binaries = [("/d/ffmpeg", "ff-d")]
    services = [("d.service", "/d/ffmpeg", 1)]
    vuln = {
        "id": "OSV-DECOY",
        "affected": [
            {"package": {"name": "ff-d", "ecosystem": "Debian"},
             "ranges": [
                 {"type": "SEMVER", "events": [{"introduced": "0"}]},
                 {"type": "ECOSYSTEM", "events": [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}]},
             ]},
            {"package": {"name": "ff-d", "ecosystem": "npm"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
            {"package": {"name": "other", "ecosystem": "Debian"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
        ],
        "database_specific": {"severity": "HIGH"},
    }
    case = run_case(tmp_path, packages, binaries, services, {"ff-d": [vuln]})
    row = case.decision("d.service")
    assert row["decision"] == "pin" and row["pin_version"] == "7:5.1.6-1"
    assert row["advisories"] == ["OSV-DECOY"]
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Decision policy
# --------------------------------------------------------------------------- #
def test_decision_policy_covers_every_branch(tmp_path: Path) -> None:
    """clean, vulnerable_fixable, no_fix, no_safe_version and unverifiable each resolve as specified."""
    packages = [
        ("ff-clean", "7:6.2.0-1", "Debian"),
        ("ff-fix", "7:5.1.4-1", "Debian"),
        ("ff-nofix", "7:5.0.0-1", "Debian"),
        ("ff-trap", "7:5.2.0-1", "Debian"),
    ]
    binaries = [
        ("/srv/clean/ffmpeg", "ff-clean"),
        ("/srv/fix/ffmpeg", "ff-fix"),
        ("/srv/nofix/ffmpeg", "ff-nofix"),
        ("/srv/trap/ffmpeg", "ff-trap"),
        ("/srv/unv/ffmpeg", None),
    ]
    services = [
        ("clean.service", "/srv/clean/ffmpeg", 1),
        ("fix.service", "/srv/fix/ffmpeg", 1),
        ("nofix.service", "/srv/nofix/ffmpeg", 1),
        ("trap.service", "/srv/trap/ffmpeg", 1),
        ("unv.service", "/srv/unv/ffmpeg", 1),
    ]
    advisories = {
        "ff-clean": [adv("OSV-C", "ff-clean", [{"introduced": "6.0"}, {"fixed": "7:6.1.0-1"}])],
        "ff-fix": [adv("OSV-F", "ff-fix", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}], "CRITICAL")],
        "ff-nofix": [adv("OSV-N", "ff-nofix", [{"introduced": "0"}])],
        "ff-trap": [
            adv("OSV-T1", "ff-trap", [{"introduced": "5.2"}, {"fixed": "7:5.2.4-1"}]),
            adv("OSV-T2", "ff-trap", [{"introduced": "7:5.2.4-1"}]),
        ],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    assert case.decision("clean.service")["decision"] == "ok"
    assert case.decision("fix.service")["decision"] == "pin"
    assert case.decision("fix.service")["pin_version"] == "7:5.1.6-1"
    assert case.decision("nofix.service")["reason"] == "no_fix"
    assert case.decision("trap.service")["reason"] == "no_safe_version"
    assert case.decision("unv.service")["reason"] == "unverifiable"
    assert_parity(case)


def test_pin_target_is_highest_fix_across_applicable_advisories(tmp_path: Path) -> None:
    """When several fixable advisories apply, the pin target is the highest of their fixes."""
    packages = [("ff-many", "7:5.0.0-1", "Debian")]
    binaries = [("/srv/many/ffmpeg", "ff-many")]
    services = [("many.service", "/srv/many/ffmpeg", 1)]
    advisories = {"ff-many": [
        adv("OSV-A", "ff-many", [{"introduced": "0"}, {"fixed": "7:5.0.3-1"}], "LOW"),
        adv("OSV-B", "ff-many", [{"introduced": "0"}, {"fixed": "7:5.0.9-1"}], "CRITICAL"),
        adv("OSV-C", "ff-many", [{"introduced": "0"}, {"fixed": "7:5.0.5-1"}], "MEDIUM"),
    ]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    row = case.decision("many.service")
    assert row["decision"] == "pin" and row["pin_version"] == "7:5.0.9-1"
    assert row["max_severity"] == "CRITICAL"
    assert row["advisories"] == ["OSV-A", "OSV-B", "OSV-C"]
    assert_parity(case)


def test_max_severity_is_highest_applicable_only(tmp_path: Path) -> None:
    """max_severity reflects applicable advisories, ignoring ones the version has moved past."""
    packages = [("ff-sev", "7:5.1.4-1", "Debian")]
    binaries = [("/srv/sev/ffmpeg", "ff-sev")]
    services = [("sev.service", "/srv/sev/ffmpeg", 1)]
    advisories = {"ff-sev": [
        adv("OSV-OLD", "ff-sev", [{"introduced": "0"}, {"fixed": "7:5.0.0-1"}], "CRITICAL"),  # already fixed
        adv("OSV-NOW", "ff-sev", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}], "MEDIUM"),   # applicable
    ]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    row = case.decision("sev.service")
    assert row["max_severity"] == "MEDIUM"
    assert row["advisories"] == ["OSV-NOW"]
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
def test_pins_are_per_package_and_use_highest_target(tmp_path: Path) -> None:
    """Two services sharing a package produce one pin file at the higher target."""
    packages = [("ff-shared", "7:5.1.4-1", "Debian")]
    binaries = [("/usr/bin/ffmpeg", "ff-shared"), ("/usr/bin/ffprobe", "ff-shared")]
    services = [("a.service", "/usr/bin/ffmpeg", 1), ("b.service", "/usr/bin/ffprobe", 1)]
    advisories = {"ff-shared": [adv("OSV-S", "ff-shared", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}], "HIGH")]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    pin_files = [name for name in case.produced if name.startswith("apt/preferences.d/")]
    assert pin_files == ["apt/preferences.d/ffguard-ff-shared.pref"]
    fields = kit.parse_pref(case.produced["apt/preferences.d/ffguard-ff-shared.pref"].decode("utf-8"))
    assert fields == {"Package": "ff-shared", "Pin": "version 7:5.1.6-1", "Pin-Priority": "1001"}
    assert_parity(case)


def test_systemd_override_paths_include_templated_units(tmp_path: Path) -> None:
    """A blocked templated unit writes a drop-in under <unit>.d/override.conf verbatim."""
    packages = [("ff-b", "7:4.0.0-1", "Debian")]
    binaries = [("/usr/bin/ffmpeg", "ff-b")]
    services = [("transcode@.service", "/usr/bin/ffmpeg", 1)]
    advisories = {"ff-b": [adv("OSV-B", "ff-b", [{"introduced": "0"}])]}
    case = run_case(tmp_path, packages, binaries, services, advisories)
    override = "systemd/system/transcode@.service.d/override.conf"
    assert override in case.produced
    sections, directives = kit.parse_override(case.produced[override].decode("utf-8"))
    assert sections == ["Service"]
    assert directives["Service.ExecStart"] == ["", "/bin/false"]
    assert directives["Service.NoNewPrivileges"] == ["yes"]
    assert directives["Service.ProtectSystem"] == ["strict"]
    assert_parity(case)


def test_report_is_canonical_json_and_sorted(tmp_path: Path) -> None:
    """The report is canonical JSON with sorted units, pins, blocked_units and a trailing newline."""
    packages = [("ff-p", "7:5.1.4-1", "Debian"), ("ff-q", "7:4.0.0-1", "Debian")]
    binaries = [
        ("/z/ffmpeg", "ff-p"), ("/a/ffmpeg", "ff-p"), ("/m/ffmpeg", "ff-q"),
    ]
    services = [
        ("zeta.service", "/z/ffmpeg", 1),
        ("alpha.service", "/a/ffmpeg", 1),
        ("mid.service", "/m/ffmpeg", 0),
    ]
    advisories = {
        "ff-p": [adv("OSV-P", "ff-p", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])],
        "ff-q": [adv("OSV-Q", "ff-q", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    body = case.produced["hardening-report.json"]
    assert body.endswith(b"\n") and not body.endswith(b"\n\n")
    assert body == case.expected["hardening-report.json"]
    report = json.loads(body)
    assert [row["unit"] for row in report["services"]] == ["alpha.service", "mid.service", "zeta.service"]
    assert report["blocked_units"] == ["mid.service"]
    assert [pin["package"] for pin in report["pins"]] == ["ff-p"]
    assert report["generated_by"] == "ffguard" and report["report_version"] == "1"
    assert_parity(case)


def test_audit_markdown_matches_reference(tmp_path: Path) -> None:
    """The Markdown audit note is byte-identical to the independently rendered note."""
    packages = [("ff-x", "7:5.1.4-1", "Debian"), ("ff-y", "7:4.0.0-1", "Debian")]
    binaries = [("/x/ffmpeg", "ff-x"), ("/y/ffmpeg", "ff-y"), ("/u/ffmpeg", None)]
    services = [
        ("x.service", "/x/ffmpeg", 1),
        ("y.service", "/y/ffmpeg", 0),
        ("u.service", "/u/ffmpeg", 1),
    ]
    advisories = {
        "ff-x": [adv("OSV-X", "ff-x", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])],
        "ff-y": [adv("OSV-Y", "ff-y", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    note = kit.parse_audit_md(case.produced["ffmpeg-hardening-audit.md"].decode("utf-8"))
    assert note == kit.parse_audit_md(case.expected["ffmpeg-hardening-audit.md"].decode("utf-8"))
    assert note["summary"] == {"Services scanned": 3, "Pinned": 1, "Blocked": 2, "Compliant": 0}
    assert [section["unit"] for section in note["sections"]] == ["u.service", "x.service", "y.service"]
    decisions = {section["unit"]: dict(section["fields"])["Decision"] for section in note["sections"]}
    assert decisions == {
        "x.service": "PINNED to 7:5.1.6-1",
        "y.service": "BLOCKED (no_fix)",
        "u.service": "BLOCKED (unverifiable)",
    }
    assert_parity(case)


def test_host_without_ffmpeg_services_is_empty(tmp_path: Path) -> None:
    """A host with no in-scope service still emits a well-formed empty report and note."""
    packages = [("nginx", "1.22.1-9", "Debian")]
    binaries = [("/usr/sbin/nginx", "nginx")]
    services = [("web.service", "/usr/sbin/nginx", 1)]
    case = run_case(tmp_path, packages, binaries, services, {})
    report = json.loads(case.produced["hardening-report.json"])
    assert report["services"] == [] and report["pins"] == [] and report["blocked_units"] == []
    assert set(case.produced) == {"hardening-report.json", "ffmpeg-hardening-audit.md"}
    assert_parity(case)


# --------------------------------------------------------------------------- #
# API integration and anti-cheat
# --------------------------------------------------------------------------- #
def test_osv_api_is_queried_once_per_resolved_package(tmp_path: Path) -> None:
    """The tool queries the advisory API exactly once per distinct resolved package —
    duplicates are preserved in case.queried, so querying ff-a twice (once per service)
    would break the equality below — and nothing is queried for unresolved or
    out-of-scope units."""
    packages = [("ff-a", "7:5.1.4-1", "Debian"), ("ff-b", "7:4.0.0-1", "Debian")]
    binaries = [
        ("/a1/ffmpeg", "ff-a"), ("/a2/ffprobe", "ff-a"), ("/b/ffmpeg", "ff-b"),
        ("/u/ffmpeg", None),
    ]
    services = [
        ("a1.service", "/a1/ffmpeg", 1),
        ("a2.service", "/a2/ffprobe", 1),
        ("b.service", "/b/ffmpeg", 1),
        ("u.service", "/u/ffmpeg", 1),          # unresolved -> not queried
        ("web.service", "/usr/sbin/nginx", 1),  # out of scope -> not queried
    ]
    binaries.append(("/usr/sbin/nginx", "nginx"))
    packages.append(("nginx", "1.22.1-9", "Debian"))
    advisories = {
        "ff-a": [adv("OSV-A", "ff-a", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])],
        "ff-b": [adv("OSV-B", "ff-b", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, packages, binaries, services, advisories)
    assert case.queried == ["ff-a", "ff-b"]
    assert_parity(case)


def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    """The same inputs always produce the same output bytes."""
    packages = [("ff", "7:5.1.4-1", "Debian")]
    binaries = [("/s/ffmpeg", "ff")]
    services = [("s.service", "/s/ffmpeg", 1)]
    advisories = {"ff": [adv("OSV", "ff", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])]}
    first = run_case(tmp_path / "one", packages, binaries, services, advisories)
    second = run_case(tmp_path / "two", packages, binaries, services, advisories)
    assert first.produced == second.produced


def test_semantic_change_changes_the_report(tmp_path: Path) -> None:
    """Changing the advisory's fixed version changes the pin target and the report bytes."""
    packages = [("ff", "7:5.1.4-1", "Debian")]
    binaries = [("/s/ffmpeg", "ff")]
    services = [("s.service", "/s/ffmpeg", 1)]
    low = {"ff": [adv("OSV", "ff", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])]}
    high = {"ff": [adv("OSV", "ff", [{"introduced": "5.1"}, {"fixed": "7:5.1.9-1"}])]}
    first = run_case(tmp_path / "a", packages, binaries, services, low)
    second = run_case(tmp_path / "b", packages, binaries, services, high)
    assert first.decision("s.service")["pin_version"] == "7:5.1.6-1"
    assert second.decision("s.service")["pin_version"] == "7:5.1.9-1"
    assert first.produced["hardening-report.json"] != second.produced["hardening-report.json"]


# --------------------------------------------------------------------------- #
# Generated hosts
# --------------------------------------------------------------------------- #
def test_generated_hosts_match_reference_oracle(tmp_path: Path) -> None:
    """Deterministically generated hosts must match the independent oracle byte for byte."""
    seen_decisions: set[str] = set()
    for seed in range(24):
        rng = random.Random(0xF17E5 + seed)
        packages, binaries, services, advisories = kit.generate_host(rng)
        case = run_case(tmp_path / f"host{seed}", packages, binaries, services, advisories)
        assert_parity(case)
        for row in case.rows:
            seen_decisions.add(f"{row['decision']}:{row['reason']}")
    # The generated corpus must exercise every decision branch at least once.
    assert {"pin:vulnerable_fixable", "block:no_fix", "block:unverifiable", "ok:clean"} <= seen_decisions


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def test_ffguard_wrapper_runs(tmp_path: Path) -> None:
    """The shipped /app/bin/ffguard wrapper drives the same tool end to end."""
    if APP != Path("/app"):
        pytest.skip("wrapper hard-codes /app; only exercised in the container")
    packages = [("ff", "7:5.1.4-1", "Debian")]
    binaries = [("/s/ffmpeg", "ff")]
    services = [("s.service", "/s/ffmpeg", 1)]
    advisories = {"ff": [adv("OSV", "ff", [{"introduced": "5.1"}, {"fixed": "7:5.1.6-1"}])]}
    db_path = tmp_path / "host_state.db"
    out_dir = tmp_path / "out"
    kit.write_db(str(db_path), packages, binaries, services)
    expected = kit.build_oracle(str(db_path), advisories)
    with kit.OsvServer(advisories) as server:
        env = os.environ.copy()
        env["HOST_STATE_DB"] = str(db_path)
        env["OSV_API_BASE"] = f"http://127.0.0.1:{server.port}"
        env["OUTPUT_DIR"] = str(out_dir)
        result = subprocess.run(["/app/bin/ffguard"], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert_artifacts_match(_collect(out_dir), expected)


def _free_default_osv_port() -> None:
    """Terminate any leftover listener on 127.0.0.1:8730 so the default
    advisory endpoint can be exercised (an agent may have left the shipped
    mirror running)."""
    inodes: set[str] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(table).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            parts = row.split()
            if len(parts) > 9 and parts[1].endswith(":221A") and parts[3] == "0A":
                inodes.add(parts[9])
    if not inodes:
        return
    targets = {f"socket:[{inode}]" for inode in inodes}
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            links = [os.readlink(fd) for fd in (pid_dir / "fd").iterdir()]
        except OSError:
            continue
        if targets.intersection(links):
            with contextlib.suppress(OSError):
                os.kill(int(pid_dir.name), signal.SIGTERM)
    time.sleep(0.5)


def test_default_configuration_fallbacks(tmp_path: Path) -> None:
    """With no overrides the tool reads /app/data/host_state.db, queries the
    advisory API at 127.0.0.1:8730 and writes under /app/out."""
    if APP != Path("/app"):
        pytest.skip("default paths are container-absolute; only exercised in the container")
    db_path = Path("/app/data/host_state.db")
    assert db_path.is_file(), "the host-state inventory must remain at /app/data/host_state.db"

    # Serve one open (unfixed) advisory per package present in the inventory so
    # every resolvable service gets a deterministic no_fix decision.
    with sqlite3.connect(db_path) as connection:
        names = [row[0] for row in connection.execute("SELECT name FROM packages")]
    advisories = {
        name: [{
            "id": f"OSV-DEFAULT-{index:02d}",
            "affected": [{"package": {"name": name, "ecosystem": "Debian"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
            "database_specific": {"severity": "HIGH"},
        }]
        for index, name in enumerate(sorted(names))
    }
    expected = kit.build_oracle(str(db_path), advisories)

    out_dir = Path("/app/out")
    shutil.rmtree(out_dir, ignore_errors=True)
    _free_default_osv_port()
    with kit.OsvServer(advisories, port=8730) as server:
        env = os.environ.copy()
        for name in ("HOST_STATE_DB", "OSV_API_BASE", "OUTPUT_DIR"):
            env.pop(name, None)
        result = subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=60)
        queried = sorted(set(server.queried))
    assert result.returncode == 0, f"tool failed on defaults: {result.stdout}\n{result.stderr}"
    assert queried, "the tool must query the default advisory endpoint on 127.0.0.1:8730"
    assert_artifacts_match(_collect(out_dir), expected)
    shutil.rmtree(out_dir, ignore_errors=True)

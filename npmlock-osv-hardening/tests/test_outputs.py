"""Black-box verifier for the npmguard dependency-remediation tool.

The verifier never imports the tool. It mints its own npm lockfiles, registry
snapshots and OSV advisory sets, serves the advisories from a mock that records
what was queried, runs the compiled command, and compares every produced
artifact against an independent Python oracle. Deterministically generated
projects make fixture-specific or hard-coded solutions insufficient.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

import npmguard_kit as kit

APP = Path(os.environ.get("APP_DIR", "/app"))
CLI = ["node", str(APP / "dist" / "cli.js")]


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
def _run_tool(lockfile: Path, registry: Path, osv_base: str, out_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["LOCKFILE_PATH"] = str(lockfile)
    env["REGISTRY_PATH"] = str(registry)
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

    def __init__(self, produced, expected, queried, findings):
        self.produced = produced
        self.expected = expected
        self.queried = queried
        self.findings = findings

    def finding(self, name: str) -> dict:
        return next(f for f in self.findings if f["name"] == name)


def run_case(base: Path, lockfile: dict, registry: dict, advisories: dict) -> Case:
    """Write the inputs, serve advisories, run the tool, and gather results."""
    base.mkdir(parents=True, exist_ok=True)
    lock_path = base / "package-lock.json"
    registry_path = base / "registry.json"
    out_dir = base / "out"
    lock_path.write_text(json.dumps(lockfile), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    expected = kit.build_oracle(lockfile, registry, advisories)
    findings = kit.findings_for(lockfile, registry, advisories)
    with kit.OsvServer(advisories) as server:
        result = _run_tool(lock_path, registry_path, f"http://127.0.0.1:{server.port}", out_dir)
        queried = sorted(set(server.queried))
    assert result.returncode == 0, f"tool failed: {result.stdout}\n{result.stderr}"
    return Case(_collect(out_dir), expected, queried, findings)


def assert_artifacts_match(produced: dict[str, bytes], expected: dict[str, bytes]) -> None:
    """Compare artifacts to the oracle: exact file set and paths, byte-exact
    canonical JSON, and parsed (content and order, not byte-layout) comparison
    for the block stanzas and the Markdown audit note."""
    assert set(produced) == set(expected), (
        f"file set mismatch; missing={sorted(set(expected) - set(produced))} "
        f"extra={sorted(set(produced) - set(expected))}"
    )
    for name, data in expected.items():
        got = produced[name]
        if name.endswith(".json"):
            assert got == data, f"canonical JSON differs for {name}"
        elif name.endswith(".deny"):
            assert kit.parse_deny(got.decode("utf-8")) == kit.parse_deny(data.decode("utf-8")), (
                f"block stanza fields differ for {name}"
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
        "affected": [{"package": {"name": pkg, "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": events}]}],
        "database_specific": {"severity": severity},
    }


def lock(root_deps: dict, nodes: dict, root_dev_deps: dict | None = None) -> dict:
    packages = {"": {"name": "p", "version": "0.0.0", "dependencies": root_deps,
                     "devDependencies": root_dev_deps or {}}}
    packages.update(nodes)
    return {"name": "p", "version": "0.0.0", "lockfileVersion": 3, "requires": True, "packages": packages}


@pytest.fixture(scope="session", autouse=True)
def _built_tool() -> None:
    """The compiled entry point must exist before any case runs."""
    assert (APP / "dist" / "cli.js").is_file(), f"missing compiled tool at {APP / 'dist' / 'cli.js'}"


# --------------------------------------------------------------------------- #
# Scope and lockfile model
# --------------------------------------------------------------------------- #
def test_dev_and_optional_packages_are_out_of_scope(tmp_path: Path) -> None:
    """Packages installed only as dev or optional dependencies never appear."""
    root = {"prod": "^1.0.0"}
    dev = {"tool": "^1.0.0", "opt": "^1.0.0"}
    nodes = {
        "node_modules/prod": {"version": "1.0.0"},
        "node_modules/tool": {"version": "1.0.0", "dev": True},
        "node_modules/opt": {"version": "1.0.0", "optional": True},
    }
    registry = {"prod": ["1.0.0", "1.1.0"], "tool": ["1.0.0", "9.0.0"], "opt": ["1.0.0", "9.0.0"]}
    advisories = {
        "prod": [],
        "tool": [adv("OSV-TOOL", "tool", [{"introduced": "0"}])],
        "opt": [adv("OSV-OPT", "opt", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, lock(root, nodes, dev), registry, advisories)
    assert [f["name"] for f in case.findings] == ["prod"]
    assert case.queried == ["prod"]
    assert_parity(case)


def test_constraints_are_gathered_from_all_nodes(tmp_path: Path) -> None:
    """A requirement declared on a non-root node still constrains the upgrade."""
    root = {"host": "^1.0.0", "left-pad": "^1.0.0"}
    nodes = {
        "node_modules/host": {"version": "1.0.0", "dependencies": {"left-pad": "~1.2.0"}},
        "node_modules/left-pad": {"version": "1.2.0"},
    }
    registry = {"host": ["1.0.0"], "left-pad": ["1.2.0", "1.2.5", "1.3.0", "2.0.0"]}
    advisories = {
        "host": [],
        "left-pad": [adv("OSV-LP", "left-pad", [{"introduced": "0"}, {"fixed": "1.2.5"}])],
    }
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("left-pad")
    # ~1.2.0 (from the host node) forbids 1.3.0/2.0.0, so the only safe upgrade is 1.2.5.
    assert finding["constraints"] == ["^1.0.0", "~1.2.0"]
    assert finding["decision"] == "upgrade" and finding["target_version"] == "1.2.5"
    assert_parity(case)


def test_scoped_package_name_and_nested_path(tmp_path: Path) -> None:
    """A scoped package nested under another resolves its name and block filename."""
    root = {"host": "^1.0.0"}
    nodes = {
        "node_modules/host": {"version": "1.0.0", "dependencies": {"@scope/util": "^1.0.0"}},
        "node_modules/host/node_modules/@scope/util": {"version": "1.0.0"},
    }
    registry = {"host": ["1.0.0"], "@scope/util": ["1.0.0"]}
    advisories = {"host": [], "@scope/util": [adv("OSV-U", "@scope/util", [{"introduced": "0"}])]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("@scope/util")
    assert finding["decision"] == "block" and finding["reason"] == "no_fix"
    assert "blocks/@scope__util.deny" in case.produced
    assert case.queried == ["@scope/util", "host"]
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Semver precedence and range satisfaction
# --------------------------------------------------------------------------- #
def test_minimal_safe_upgrade_is_selected(tmp_path: Path) -> None:
    """The upgrade target is the lowest unaffected version satisfying every range."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.4.0", "1.5.0", "1.9.0", "2.0.0"]}
    advisories = {"lib": [adv("OSV-L", "lib", [{"introduced": "0"}, {"fixed": "1.4.0"}])]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("lib")
    # 1.4.0, 1.5.0 and 1.9.0 all qualify; the lowest wins. 2.0.0 breaks ^1.0.0.
    assert finding["decision"] == "upgrade" and finding["target_version"] == "1.4.0"
    assert_parity(case)


def test_prerelease_versions_do_not_satisfy_plain_ranges(tmp_path: Path) -> None:
    """A pre-release registry entry is not chosen when the range carries no matching pre-release."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.5.0-rc.1", "1.5.0"]}
    advisories = {"lib": [adv("OSV-P", "lib", [{"introduced": "0"}, {"fixed": "1.5.0"}])]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("lib")
    # 1.5.0-rc.1 is unaffected and lower than 1.5.0, but ^1.0.0 excludes pre-releases.
    assert finding["target_version"] == "1.5.0"
    assert_parity(case)


def test_zero_major_caret_is_narrow(tmp_path: Path) -> None:
    """^0.2.x only admits 0.2.z, so a 0.3.0 fix cannot satisfy it."""
    root = {"lib": "^0.2.0"}
    nodes = {"node_modules/lib": {"version": "0.2.0"}}
    registry = {"lib": ["0.2.0", "0.2.5", "0.3.0"]}
    advisories = {"lib": [adv("OSV-Z", "lib", [{"introduced": "0"}, {"fixed": "0.2.5"}])]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("lib")
    assert finding["decision"] == "upgrade" and finding["target_version"] == "0.2.5"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# OSV range containment
# --------------------------------------------------------------------------- #
def test_multi_interval_reintroduction_is_contained(tmp_path: Path) -> None:
    """A version in a reintroduced interval upgrades past that interval's fix."""
    root = {"lib": ">=1.0.0"}
    nodes = {"node_modules/lib": {"version": "2.2.0"}}
    registry = {"lib": ["2.2.0", "2.5.0", "3.0.0"]}
    events = [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "2.5.0"}]
    advisories = {"lib": [adv("OSV-M", "lib", events)]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("lib")
    assert finding["decision"] == "upgrade" and finding["target_version"] == "2.5.0"
    assert_parity(case)


def test_open_and_last_affected_ranges_block_when_unfixable(tmp_path: Path) -> None:
    """Open and last_affected intervals with no clearing version block as no_fix."""
    root = {"a": "^1.0.0", "b": "^1.0.0"}
    nodes = {"node_modules/a": {"version": "1.0.0"}, "node_modules/b": {"version": "1.0.0"}}
    registry = {"a": ["1.0.0", "1.1.0"], "b": ["1.0.0", "1.1.0"]}
    advisories = {
        "a": [adv("OSV-OPEN", "a", [{"introduced": "0"}])],
        "b": [adv("OSV-LAST", "b", [{"introduced": "0"}, {"last_affected": "9.9.9"}])],
    }
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    assert case.finding("a")["reason"] == "no_fix"
    assert case.finding("b")["reason"] == "no_fix"
    assert_parity(case)


def test_withdrawn_and_foreign_records_are_ignored(tmp_path: Path) -> None:
    """Withdrawn advisories, non-SEMVER ranges and foreign ecosystems never apply."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.6.0"]}
    live = adv("OSV-LIVE", "lib", [{"introduced": "0"}, {"fixed": "1.6.0"}], "HIGH")
    dead = adv("OSV-DEAD", "lib", [{"introduced": "0"}, {"fixed": "9.0.0"}], "CRITICAL")
    dead["withdrawn"] = "2026-01-01T00:00:00Z"
    decoy = {
        "id": "OSV-DECOY",
        "affected": [
            {"package": {"name": "lib", "ecosystem": "npm"},
             "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]},
            {"package": {"name": "lib", "ecosystem": "PyPI"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
        ],
        "database_specific": {"severity": "CRITICAL"},
    }
    case = run_case(tmp_path, lock(root, nodes), registry, {"lib": [live, dead, decoy]})
    finding = case.finding("lib")
    assert finding["advisories"] == ["OSV-LIVE"] and finding["max_severity"] == "HIGH"
    assert finding["target_version"] == "1.6.0"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Decision policy
# --------------------------------------------------------------------------- #
def test_decision_policy_covers_every_branch(tmp_path: Path) -> None:
    """clean, vulnerable_fixable, no_fix and no_safe_version each resolve as specified."""
    root = {"clean": "^3.0.0", "fix": "^1.0.0", "nofix": "^1.0.0", "trap": "=2.0.0"}
    nodes = {
        "node_modules/clean": {"version": "3.2.0"},
        "node_modules/fix": {"version": "1.0.0"},
        "node_modules/nofix": {"version": "1.0.0"},
        "node_modules/trap": {"version": "2.0.0"},
    }
    registry = {
        "clean": ["3.0.0", "3.2.0"],
        "fix": ["1.0.0", "1.4.0"],
        "nofix": ["1.0.0", "1.9.0"],
        "trap": ["2.0.0", "2.4.0", "2.5.0"],
    }
    advisories = {
        "clean": [adv("OSV-C", "clean", [{"introduced": "0"}, {"fixed": "3.0.0"}])],
        "fix": [adv("OSV-F", "fix", [{"introduced": "0"}, {"fixed": "1.4.0"}], "CRITICAL")],
        "nofix": [adv("OSV-N", "nofix", [{"introduced": "0"}])],
        "trap": [adv("OSV-T", "trap", [{"introduced": "0"}, {"fixed": "2.4.0"}])],
    }
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    assert case.finding("clean")["decision"] == "ok"
    assert case.finding("fix")["decision"] == "upgrade" and case.finding("fix")["target_version"] == "1.4.0"
    assert case.finding("nofix")["reason"] == "no_fix"
    # 2.4.0/2.5.0 clear the advisory but =2.0.0 admits neither -> no_safe_version.
    assert case.finding("trap")["reason"] == "no_safe_version"
    assert_parity(case)


def test_max_severity_is_over_applicable_only(tmp_path: Path) -> None:
    """max_severity reflects applicable advisories, ignoring ones already cleared."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.4.0"}}
    registry = {"lib": ["1.4.0", "1.6.0"]}
    advisories = {"lib": [
        adv("OSV-OLD", "lib", [{"introduced": "0"}, {"fixed": "1.2.0"}], "CRITICAL"),  # already fixed
        adv("OSV-NOW", "lib", [{"introduced": "1.3.0"}, {"fixed": "1.6.0"}], "MEDIUM"),  # applicable
    ]}
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    finding = case.finding("lib")
    assert finding["advisories"] == ["OSV-NOW"] and finding["max_severity"] == "MEDIUM"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
def test_report_is_canonical_json_and_sorted(tmp_path: Path) -> None:
    """The report is canonical JSON with sorted packages, overrides, blocked and a trailing newline."""
    root = {"zeta": "^1.0.0", "alpha": "^1.0.0"}
    nodes = {"node_modules/zeta": {"version": "1.0.0"}, "node_modules/alpha": {"version": "1.0.0"}}
    registry = {"zeta": ["1.0.0", "1.2.0"], "alpha": ["1.0.0"]}
    advisories = {
        "zeta": [adv("OSV-Z", "zeta", [{"introduced": "0"}, {"fixed": "1.2.0"}])],
        "alpha": [adv("OSV-A", "alpha", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    body = case.produced["remediation-report.json"]
    assert body.endswith(b"\n") and not body.endswith(b"\n\n")
    assert body == case.expected["remediation-report.json"]
    report = json.loads(body)
    assert [f["name"] for f in report["packages"]] == ["alpha", "zeta"]
    assert report["blocked"] == ["alpha"]
    assert report["overrides"] == {"zeta": "1.2.0"}
    assert report["generated_by"] == "npmguard" and report["report_version"] == "1"
    assert case.produced["overrides.json"] == kit.canonical_json({"overrides": {"zeta": "1.2.0"}})
    assert_parity(case)


def test_audit_markdown_matches_reference(tmp_path: Path) -> None:
    """The Markdown audit note matches the independently rendered note."""
    root = {"up": "^1.0.0", "stay": "^2.0.0", "no": "^1.0.0"}
    nodes = {
        "node_modules/up": {"version": "1.0.0"},
        "node_modules/stay": {"version": "2.5.0"},
        "node_modules/no": {"version": "1.0.0"},
    }
    registry = {"up": ["1.0.0", "1.3.0"], "stay": ["2.0.0", "2.5.0"], "no": ["1.0.0"]}
    advisories = {
        "up": [adv("OSV-UP", "up", [{"introduced": "0"}, {"fixed": "1.3.0"}])],
        "stay": [adv("OSV-ST", "stay", [{"introduced": "0"}, {"fixed": "2.0.0"}])],
        "no": [adv("OSV-NO", "no", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, lock(root, nodes), registry, advisories)
    note = kit.parse_audit_md(case.produced["remediation-audit.md"].decode("utf-8"))
    assert note["summary"] == {"Packages audited": 3, "Upgraded": 1, "Blocked": 1, "Clean": 1}
    assert [section["name"] for section in note["sections"]] == ["no", "stay", "up"]
    decisions = {s["name"]: dict(s["fields"])["Decision"] for s in note["sections"]}
    assert decisions == {"up": "UPGRADE to 1.3.0", "stay": "CLEAN", "no": "BLOCKED (no_fix)"}
    assert_parity(case)


def test_project_without_findings_is_empty(tmp_path: Path) -> None:
    """A project whose only dependency is clean still emits a well-formed report."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0"]}
    case = run_case(tmp_path, lock(root, nodes), registry, {"lib": []})
    report = json.loads(case.produced["remediation-report.json"])
    assert report["blocked"] == [] and report["overrides"] == {}
    assert set(case.produced) == {"remediation-report.json", "overrides.json", "remediation-audit.md"}
    assert_parity(case)


# --------------------------------------------------------------------------- #
# API integration and anti-cheat
# --------------------------------------------------------------------------- #
def test_osv_is_queried_once_per_in_scope_package(tmp_path: Path) -> None:
    """The tool queries the advisory API for each in-scope package and nothing else."""
    root = {"a": "^1.0.0", "b": "^1.0.0"}
    dev = {"d": "^1.0.0"}
    nodes = {
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/b": {"version": "1.0.0"},
        "node_modules/d": {"version": "1.0.0", "dev": True},
    }
    registry = {"a": ["1.0.0", "1.2.0"], "b": ["1.0.0"], "d": ["1.0.0"]}
    advisories = {
        "a": [adv("OSV-A", "a", [{"introduced": "0"}, {"fixed": "1.2.0"}])],
        "b": [],
        "d": [adv("OSV-D", "d", [{"introduced": "0"}])],
    }
    case = run_case(tmp_path, lock(root, nodes, dev), registry, advisories)
    assert case.queried == ["a", "b"]
    assert_parity(case)


def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    """The same inputs always produce the same output bytes."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.2.0"]}
    advisories = {"lib": [adv("OSV", "lib", [{"introduced": "0"}, {"fixed": "1.2.0"}])]}
    first = run_case(tmp_path / "one", lock(root, nodes), registry, advisories)
    second = run_case(tmp_path / "two", lock(root, nodes), registry, advisories)
    assert first.produced == second.produced


def test_semantic_change_changes_the_report(tmp_path: Path) -> None:
    """Changing the advisory fix changes the upgrade target and the report bytes."""
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.2.0", "1.5.0"]}
    low = {"lib": [adv("OSV", "lib", [{"introduced": "0"}, {"fixed": "1.2.0"}])]}
    high = {"lib": [adv("OSV", "lib", [{"introduced": "0"}, {"fixed": "1.5.0"}])]}
    first = run_case(tmp_path / "a", lock(root, nodes), registry, low)
    second = run_case(tmp_path / "b", lock(root, nodes), registry, high)
    assert first.finding("lib")["target_version"] == "1.2.0"
    assert second.finding("lib")["target_version"] == "1.5.0"
    assert first.produced["remediation-report.json"] != second.produced["remediation-report.json"]


# --------------------------------------------------------------------------- #
# Generated projects
# --------------------------------------------------------------------------- #
def test_generated_projects_match_reference_oracle(tmp_path: Path) -> None:
    """Deterministically generated projects must match the independent oracle byte for byte."""
    seen: set[str] = set()
    for seed in range(24):
        rng = random.Random(0x9B70C + seed)
        lockfile, registry, advisories = kit.generate_project(rng)
        case = run_case(tmp_path / f"proj{seed}", lockfile, registry, advisories)
        assert_parity(case)
        for finding in case.findings:
            seen.add(f"{finding['decision']}:{finding['reason']}")
    assert {"upgrade:vulnerable_fixable", "block:no_fix", "block:no_safe_version", "ok:clean"} <= seen


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def test_npmguard_wrapper_runs(tmp_path: Path) -> None:
    """The shipped /app/bin/npmguard wrapper drives the same tool end to end."""
    if APP != Path("/app"):
        pytest.skip("wrapper hard-codes /app; only exercised in the container")
    root = {"lib": "^1.0.0"}
    nodes = {"node_modules/lib": {"version": "1.0.0"}}
    registry = {"lib": ["1.0.0", "1.2.0"]}
    advisories = {"lib": [adv("OSV", "lib", [{"introduced": "0"}, {"fixed": "1.2.0"}])]}
    lock_path = tmp_path / "package-lock.json"
    registry_path = tmp_path / "registry.json"
    out_dir = tmp_path / "out"
    lock_path.write_text(json.dumps(lock(root, nodes)), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    expected = kit.build_oracle(lock(root, nodes), registry, advisories)
    with kit.OsvServer(advisories) as server:
        env = os.environ.copy()
        env["LOCKFILE_PATH"] = str(lock_path)
        env["REGISTRY_PATH"] = str(registry_path)
        env["OSV_API_BASE"] = f"http://127.0.0.1:{server.port}"
        env["OUTPUT_DIR"] = str(out_dir)
        result = subprocess.run(["/app/bin/npmguard"], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert_artifacts_match(_collect(out_dir), expected)


def _free_default_osv_port() -> None:
    """Terminate any leftover listener on 127.0.0.1:8730 so the default advisory
    endpoint can be bound (an agent may have left the shipped mirror running)."""
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
    """With no overrides the tool reads /app/data, queries 127.0.0.1:8730 and writes under /app/out."""
    if APP != Path("/app"):
        pytest.skip("default paths are container-absolute; only exercised in the container")
    lock_path = Path("/app/data/package-lock.json")
    registry_path = Path("/app/data/registry.json")
    assert lock_path.is_file() and registry_path.is_file()
    lockfile = json.loads(lock_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    # Serve one open advisory per registry package so every resolvable package
    # gets a deterministic decision from the default endpoint.
    advisories = {
        name: [{"id": f"OSV-DEFAULT-{index:02d}",
                "affected": [{"package": {"name": name, "ecosystem": "npm"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
                "database_specific": {"severity": "HIGH"}}]
        for index, name in enumerate(sorted(registry))
    }
    expected = kit.build_oracle(lockfile, registry, advisories)

    out_dir = Path("/app/out")
    shutil.rmtree(out_dir, ignore_errors=True)
    _free_default_osv_port()
    with kit.OsvServer(advisories, port=8730) as server:
        env = os.environ.copy()
        for name in ("LOCKFILE_PATH", "REGISTRY_PATH", "OSV_API_BASE", "OUTPUT_DIR"):
            env.pop(name, None)
        result = subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=60)
        queried = sorted(set(server.queried))
    assert result.returncode == 0, f"tool failed on defaults: {result.stdout}\n{result.stderr}"
    assert queried, "the tool must query the default advisory endpoint on 127.0.0.1:8730"
    assert_artifacts_match(_collect(out_dir), expected)
    shutil.rmtree(out_dir, ignore_errors=True)

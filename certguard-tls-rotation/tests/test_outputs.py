"""Black-box verifier for the certguard TLS-hardening tool.

The verifier never imports the tool. It mints its own TLS inventories and CRL
sets, serves the CRLs from a mock that records which issuers were queried, runs
the compiled command, and compares every produced artifact against an independent
Python oracle. Deterministically generated inventories make fixture-specific or
hard-coded solutions insufficient.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

import certkit as kit

APP = Path(os.environ.get("APP_DIR", "/app"))


def _cli() -> list[str]:
    for name in ("certguard.exe", "certguard"):
        candidate = APP / "bin" / name
        if candidate.exists():
            return [str(candidate)]
    return [str(APP / "bin" / "certguard")]


CLI = _cli()

# Fixed instants used across the hand-written fixtures.
T = "2026-07-01T00:00:00Z"
ROOT_NB, ROOT_NA = "2015-01-01T00:00:00Z", "2035-01-01T00:00:00Z"
WIDE_NB, WIDE_NA = "2024-01-01T00:00:00Z", "2030-01-01T00:00:00Z"
FRESH_NA = "2027-06-01T00:00:00Z"
EXPIRING_NA = "2026-07-15T00:00:00Z"   # 14 days after T, inside a 30-day window
EXPIRED_NA = "2026-05-01T00:00:00Z"
LEAF_NB = "2026-01-01T00:00:00Z"


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #
def ca(cid, ski, aki, nb=WIDE_NB, na=WIDE_NA, path_len=None, nc=None, eku=None, ku=None, serial="1"):
    return {
        "id": cid, "subject": cid, "subject_key_id": ski, "authority_key_id": aki,
        "serial": serial, "not_before": nb, "not_after": na, "is_ca": True, "path_len": path_len,
        "key_usages": ku if ku is not None else ["certSign", "crlSign"],
        "ext_key_usages": eku or [], "sans": [], "name_constraints": nc,
    }


def leaf(cid, ski, aki, sans, nb=LEAF_NB, na=FRESH_NA, serial="100", eku=None):
    return {
        "id": cid, "subject": sans[0] if sans else cid, "subject_key_id": ski, "authority_key_id": aki,
        "serial": serial, "not_before": nb, "not_after": na, "is_ca": False, "path_len": None,
        "key_usages": ["digitalSignature"], "ext_key_usages": ["serverAuth"] if eku is None else eku,
        "sans": sans, "name_constraints": None,
    }


def svc(unit, name, bound, enabled=True):
    return {"unit": unit, "server_name": name, "bound_id": bound, "enabled": enabled}


def inventory(certs, services, trust, evaluated_at=T, window=30):
    return {
        "certificates": certs, "services": services, "trust_store": trust,
        "policy": {"evaluated_at": evaluated_at, "rotation_window_days": window},
    }


def crl(issuer, entries, this_update="2026-06-20T00:00:00Z", next_update="2026-07-20T00:00:00Z"):
    return {issuer: {"issuer_key_id": issuer, "this_update": this_update,
                     "next_update": next_update, "entries": entries}}


# A trusted two-level PKI reused by many fixtures: root "R" (anchor) issues
# intermediate "I" which issues leaves. The name-constrained variant permits
# only example.internal.
def base_pki(nc=None, int_path_len=None, int_eku=None):
    return [
        ca("root", "R", "R", nb=ROOT_NB, na=ROOT_NA),
        ca("intermediate", "I", "R", path_len=int_path_len, nc=nc, eku=int_eku),
    ]


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
def _run_tool(inv_dir: Path, base: str, out_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["INVENTORY_DIR"] = str(inv_dir)
    env["REVOCATION_API_BASE"] = base
    env["OUTPUT_DIR"] = str(out_dir)
    return subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=60)


def _collect(out_dir: Path) -> dict[str, bytes]:
    produced: dict[str, bytes] = {}
    for path in out_dir.rglob("*"):
        if path.is_file():
            produced[str(path.relative_to(out_dir)).replace(os.sep, "/")] = path.read_bytes()
    return produced


class Case:
    def __init__(self, produced, expected, queried, rows, exp_queries):
        self.produced = produced
        self.expected = expected
        self.queried = queried
        self.rows = rows
        self.exp_queries = exp_queries

    def decision(self, unit: str) -> dict:
        return next(row for row in self.rows if row["unit"] == unit)


def run_case(base: Path, inv_data: dict, crls: dict | None = None) -> Case:
    crls = crls or {}
    base.mkdir(parents=True, exist_ok=True)
    inv_dir = base / "inv"
    out_dir = base / "out"
    kit.write_inventory(str(inv_dir), inv_data)
    inv = kit.Inventory(inv_data)
    expected = kit.build_oracle(inv, crls)
    rows = kit.evaluate(inv, crls)
    exp_queries = sorted(kit.expected_queries(inv))
    with kit.RevocationServer(crls) as server:
        result = _run_tool(inv_dir, f"http://127.0.0.1:{server.port}", out_dir)
        queried = sorted(set(server.queried))
    assert result.returncode == 0, f"tool failed: {result.stdout}\n{result.stderr}"
    return Case(_collect(out_dir), expected, queried, rows, exp_queries)


def assert_artifacts_match(produced: dict[str, bytes], expected: dict[str, bytes]) -> None:
    """Exact file set and paths, and every required artifact compared byte for byte
    (the canonical JSON report, the nginx snippets, the systemd drop-ins and the
    Markdown audit)."""
    assert set(produced) == set(expected), (
        f"file set mismatch; missing={sorted(set(expected) - set(produced))} "
        f"extra={sorted(set(produced) - set(expected))}"
    )
    for name, data in expected.items():
        assert produced[name] == data, f"bytes differ for {name}"


def assert_parity(case: Case) -> None:
    assert_artifacts_match(case.produced, case.expected)
    assert case.queried == case.exp_queries, (
        f"CRL query set differs; expected {case.exp_queries}, got {case.queried}"
    )


@pytest.fixture(scope="session", autouse=True)
def _built_tool() -> None:
    """The compiled entry point must exist before any case runs."""
    assert (APP / "bin" / "certguard").is_file() or (APP / "bin" / "certguard.exe").is_file(), (
        f"missing compiled tool at {APP / 'bin' / 'certguard'}"
    )


# --------------------------------------------------------------------------- #
# Canonical report and fingerprints
# --------------------------------------------------------------------------- #
def test_report_is_canonical_json_and_sorted(tmp_path: Path) -> None:
    """The report is canonical JSON: recursively key-sorted, unit-sorted services, one trailing newline."""
    certs = base_pki() + [
        leaf("z", "z1", "I", ["zeta.example.internal"]),
        leaf("a", "a1", "I", ["alpha.example.internal"]),
    ]
    services = [svc("zeta.service", "zeta.example.internal", "z"), svc("alpha.service", "alpha.example.internal", "a")]
    case = run_case(tmp_path, inventory(certs, services, ["R"]))
    body = case.produced["tls-trust-report.json"]
    assert body.endswith(b"\n") and not body.endswith(b"\n\n")
    report = json.loads(body)
    assert [s["unit"] for s in report["services"]] == ["alpha.service", "zeta.service"]
    assert report["generated_by"] == "certguard" and report["report_version"] == "1"
    assert report["evaluated_at"] == T
    assert body == case.expected["tls-trust-report.json"]
    assert_parity(case)


def test_fingerprint_is_load_bearing(tmp_path: Path) -> None:
    """The bound_fingerprint the tool reports matches the independent SHA-256 fingerprint."""
    lf = leaf("c", "c1", "I", ["host.example.internal"])
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("s.service", "host.example.internal", "c")], ["R"]))
    report = json.loads(case.produced["tls-trust-report.json"])
    entry = report["services"][0]
    assert entry["bound_fingerprint"] == kit.fingerprint(lf)
    assert entry["chain"][0] == kit.fingerprint(lf)


def test_empty_inventory_is_well_formed(tmp_path: Path) -> None:
    """A host with no services still emits a well-formed empty report and note."""
    case = run_case(tmp_path, inventory(base_pki(), [], ["R"]))
    report = json.loads(case.produced["tls-trust-report.json"])
    assert report["services"] == [] and report["rotations"] == [] and report["blocked_units"] == []
    assert set(case.produced) == {"tls-trust-report.json", "tls-rotation-audit.md"}
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Chain building and validity
# --------------------------------------------------------------------------- #
def test_compliant_service_needs_no_action(tmp_path: Path) -> None:
    """A leaf with a valid, fresh, unrevoked chain to a trusted anchor is compliant."""
    lf = leaf("c", "c1", "I", ["ok.example.internal"], na=FRESH_NA)
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("ok.service", "ok.example.internal", "c")], ["R"]))
    row = case.decision("ok.service")
    assert row["decision"] == "ok" and row["reason"] == "compliant"
    assert set(case.produced) == {"tls-trust-report.json", "tls-rotation-audit.md"}
    assert_parity(case)


def test_untrusted_when_chain_reaches_no_anchor(tmp_path: Path) -> None:
    """A leaf whose issuer chain never reaches a trusted anchor is untrusted."""
    certs = [
        ca("ext-root", "XR", "XR", nb=ROOT_NB, na=ROOT_NA),
        ca("ext-int", "XI", "XR"),
        leaf("c", "c1", "XI", ["p.example.internal"]),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("p.service", "p.example.internal", "c")], ["R"]))
    row = case.decision("p.service")
    assert row["decision"] == "block" and row["reason"] == "untrusted"
    assert row["anchored"] is False and row["chain"] == []
    assert_parity(case)


def test_intermediate_out_of_validity_is_untrusted(tmp_path: Path) -> None:
    """An expired intermediate invalidates the chain even when the leaf is valid."""
    certs = [
        ca("root", "R", "R", nb=ROOT_NB, na=ROOT_NA),
        ca("intermediate", "I", "R", nb=WIDE_NB, na=EXPIRED_NA),   # intermediate already expired
        leaf("c", "c1", "I", ["q.example.internal"]),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("q.service", "q.example.internal", "c")], ["R"]))
    assert case.decision("q.service")["reason"] == "untrusted"
    assert_parity(case)


def test_path_length_constraint_is_enforced(tmp_path: Path) -> None:
    """A pathlen:0 intermediate cannot have another CA beneath it."""
    certs = [
        ca("root", "R", "R", nb=ROOT_NB, na=ROOT_NA),
        ca("intermediate", "I", "R", path_len=0),
        ca("sub", "S", "I"),
        leaf("c", "c1", "S", ["d.example.internal"]),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("d.service", "d.example.internal", "c")], ["R"]))
    assert case.decision("d.service")["reason"] == "untrusted"
    assert_parity(case)


def test_valid_multilevel_chain_builds_to_anchor(tmp_path: Path) -> None:
    """A leaf under a sub-CA beneath a pathlen-1 intermediate builds a four-certificate
    chain to the anchor; an expiring one on that deep chain rotates onto a fresh peer."""
    certs = [
        ca("root", "R", "R", nb=ROOT_NB, na=ROOT_NA),
        ca("intermediate", "I", "R", path_len=1),
        ca("sub", "S", "I", path_len=0),
        leaf("bound", "b1", "S", ["deep.example.internal"], na=EXPIRING_NA, serial="1"),
        leaf("fresh", "f1", "S", ["deep.example.internal"], na=FRESH_NA, serial="2"),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("deep.service", "deep.example.internal", "bound")], ["R"]))
    row = case.decision("deep.service")
    assert row["decision"] == "rotate" and row["reason"] == "expiring"
    assert row["anchored"] is True and len(row["chain"]) == 4
    assert row["chain"][0] == kit.fingerprint(certs[3]) and row["chain"][-1] == kit.fingerprint(certs[0])
    assert row["replacement_fingerprint"] == kit.fingerprint(certs[4])
    assert "nginx/snippets/deep.service.conf" in case.produced
    assert_parity(case)


def test_extended_key_usage_must_chain(tmp_path: Path) -> None:
    """An intermediate restricted to a non-serverAuth EKU breaks a serverAuth chain."""
    certs = base_pki(int_eku=["clientAuth"]) + [leaf("c", "c1", "I", ["e.example.internal"])]
    case = run_case(tmp_path, inventory(certs, [svc("e.service", "e.example.internal", "c")], ["R"]))
    assert case.decision("e.service")["reason"] == "untrusted"
    assert_parity(case)


def test_name_constraints_permit_and_exclude(tmp_path: Path) -> None:
    """A permitted subtree that excludes the identity, or an excluded subtree that matches it, is untrusted."""
    permit = base_pki(nc={"permitted": ["corp.internal"], "excluded": []}) + [
        leaf("c", "c1", "I", ["host.example.internal"]),
    ]
    case = run_case(tmp_path / "permit", inventory(permit, [svc("s.service", "host.example.internal", "c")], ["R"]))
    assert case.decision("s.service")["reason"] == "untrusted"
    assert_parity(case)

    exclude = base_pki(nc={"permitted": [], "excluded": ["host.example.internal"]}) + [
        leaf("c", "c1", "I", ["host.example.internal"]),
    ]
    case2 = run_case(tmp_path / "exclude", inventory(exclude, [svc("s.service", "host.example.internal", "c")], ["R"]))
    assert case2.decision("s.service")["reason"] == "untrusted"
    assert_parity(case2)


def test_wildcard_san_matches_one_label_only(tmp_path: Path) -> None:
    """A *.a.example.internal SAN covers one left label, not a bare or multi-label name."""
    wild = leaf("c", "c1", "I", ["*.a.example.internal"])
    good = run_case(tmp_path / "one", inventory(base_pki() + [wild], [svc("s.service", "x.a.example.internal", "c")], ["R"]))
    assert good.decision("s.service")["decision"] == "ok"
    assert_parity(good)

    deep = run_case(tmp_path / "deep", inventory(base_pki() + [wild], [svc("s.service", "x.y.a.example.internal", "c")], ["R"]))
    assert deep.decision("s.service")["reason"] == "untrusted"
    assert_parity(deep)


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #
def test_current_crl_revokes_by_value(tmp_path: Path) -> None:
    """A current CRL listing the leaf serial (in any numeric form) revokes it."""
    lf = leaf("c", "c1", "I", ["m.example.internal"], serial="0x1a2b")
    crls = crl("I", [{"serial": str(int("1a2b", 16)), "reason": "keyCompromise"}])
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("m.service", "m.example.internal", "c")], ["R"]), crls)
    assert case.decision("m.service")["reason"] == "revoked"
    assert_parity(case)


def test_stale_crl_fails_closed(tmp_path: Path) -> None:
    """A CRL whose window does not cover T yields unknown status and blocks the certificate."""
    lf = leaf("c", "c1", "I", ["v.example.internal"], serial="55")
    crls = crl("I", [], this_update="2026-01-01T00:00:00Z", next_update="2026-02-01T00:00:00Z")  # expired window
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("v.service", "v.example.internal", "c")], ["R"]), crls)
    assert case.decision("v.service")["reason"] == "revoked"
    assert_parity(case)


def test_remove_from_crl_unrevokes(tmp_path: Path) -> None:
    """An entry with reason removeFromCRL does not revoke the certificate."""
    lf = leaf("c", "c1", "I", ["r.example.internal"], serial="77")
    crls = crl("I", [{"serial": "77", "reason": "removeFromCRL"}])
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("r.service", "r.example.internal", "c")], ["R"]), crls)
    assert case.decision("r.service")["decision"] == "ok"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Decision policy, rotation and selection
# --------------------------------------------------------------------------- #
def test_expiring_rotates_when_replacement_exists(tmp_path: Path) -> None:
    """A soon-to-expire leaf rotates onto a fresh replacement covering the identity."""
    certs = base_pki() + [
        leaf("old", "o1", "I", ["w.example.internal"], na=EXPIRING_NA, serial="10"),
        leaf("new", "n1", "I", ["w.example.internal"], na=FRESH_NA, serial="11"),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("w.service", "w.example.internal", "old")], ["R"]))
    row = case.decision("w.service")
    assert row["decision"] == "rotate" and row["reason"] == "expiring"
    assert row["replacement_fingerprint"] == kit.fingerprint(certs[3])
    assert "nginx/snippets/w.service.conf" in case.produced
    assert_parity(case)


def test_expiring_blocks_without_replacement(tmp_path: Path) -> None:
    """A soon-to-expire leaf with no fresh replacement is blocked."""
    certs = base_pki() + [leaf("old", "o1", "I", ["w.example.internal"], na=EXPIRING_NA)]
    case = run_case(tmp_path, inventory(certs, [svc("w.service", "w.example.internal", "old")], ["R"]))
    row = case.decision("w.service")
    assert row["decision"] == "block" and row["reason"] == "expiring"
    assert "systemd/system/w.service.d/override.conf" in case.produced
    assert_parity(case)


def test_missing_bound_certificate(tmp_path: Path) -> None:
    """A service bound to an absent certificate rotates if a replacement exists, else blocks."""
    certs = base_pki() + [leaf("repl", "r1", "I", ["s.example.internal"])]
    rotate = run_case(tmp_path / "r", inventory(certs, [svc("s.service", "s.example.internal", "nope")], ["R"]))
    assert rotate.decision("s.service")["decision"] == "rotate" and rotate.decision("s.service")["reason"] == "missing"
    assert_parity(rotate)

    block = run_case(tmp_path / "b", inventory(base_pki(), [svc("s.service", "s.example.internal", "nope")], ["R"]))
    assert block.decision("s.service")["decision"] == "block" and block.decision("s.service")["reason"] == "missing"
    assert block.decision("s.service")["chain"] == [] and block.decision("s.service")["bound_fingerprint"] is None
    assert_parity(block)


def test_replacement_selection_prefers_latest_then_serial(tmp_path: Path) -> None:
    """Among candidates the tool picks the latest not_after, breaking ties by larger serial."""
    certs = base_pki() + [
        leaf("bound", "b1", "I", ["sel.example.internal"], na=EXPIRED_NA, serial="1"),   # expired -> needs rotation
        leaf("cand-early", "e1", "I", ["sel.example.internal"], na="2027-01-01T00:00:00Z", serial="9"),
        leaf("cand-late-lo", "l1", "I", ["sel.example.internal"], na="2028-01-01T00:00:00Z", serial="2"),
        leaf("cand-late-hi", "h1", "I", ["sel.example.internal"], na="2028-01-01T00:00:00Z", serial="8"),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("sel.service", "sel.example.internal", "bound")], ["R"]))
    row = case.decision("sel.service")
    assert row["decision"] == "rotate"
    # latest not_after is 2028; tie broken by the larger serial (8)
    assert row["replacement_fingerprint"] == kit.fingerprint(certs[5])
    assert_parity(case)


def test_replacement_tie_break_by_fingerprint(tmp_path: Path) -> None:
    """When two candidates share not_after and serial, the larger fingerprint wins the tie."""
    cand_a = leaf("cand-a", "ta", "I", ["tie.example.internal"], na="2028-01-01T00:00:00Z", serial="7")
    cand_b = leaf("cand-b", "tb", "I", ["tie.example.internal"], na="2028-01-01T00:00:00Z", serial="7")
    certs = base_pki() + [
        leaf("bound", "b1", "I", ["tie.example.internal"], na=EXPIRED_NA, serial="1"),  # expired -> rotate
        cand_a,
        cand_b,
    ]
    case = run_case(tmp_path, inventory(certs, [svc("tie.service", "tie.example.internal", "bound")], ["R"]))
    winner = max([cand_a, cand_b], key=kit.fp_hex)
    row = case.decision("tie.service")
    assert row["decision"] == "rotate"
    assert row["replacement_fingerprint"] == kit.fingerprint(winner)
    assert_parity(case)


def test_decision_policy_covers_every_branch(tmp_path: Path) -> None:
    """compliant, expiring, expired, revoked, untrusted and missing each resolve as specified."""
    certs = base_pki() + [
        leaf("clean", "c1", "I", ["clean.example.internal"], na=FRESH_NA),
        leaf("exp", "x1", "I", ["exp.example.internal"], na=EXPIRED_NA),
        leaf("rev", "v1", "I", ["rev.example.internal"], serial="500"),
    ]
    services = [
        svc("clean.service", "clean.example.internal", "clean"),
        svc("exp.service", "exp.example.internal", "exp"),
        svc("rev.service", "rev.example.internal", "rev"),
        svc("gone.service", "gone.example.internal", "absent"),
    ]
    crls = crl("I", [{"serial": "500", "reason": "keyCompromise"}])
    case = run_case(tmp_path, inventory(certs, services, ["R"]), crls)
    assert case.decision("clean.service")["decision"] == "ok"
    assert case.decision("exp.service")["reason"] == "expired"
    assert case.decision("rev.service")["reason"] == "revoked"
    assert case.decision("gone.service")["reason"] == "missing"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
def test_templated_block_unit_uses_directory(tmp_path: Path) -> None:
    """A blocked templated unit writes systemd/system/<unit>.d/override.conf verbatim."""
    certs = [ca("ext", "XR", "XR", nb=ROOT_NB, na=ROOT_NA), leaf("c", "c1", "XR-none", ["t.example.internal"])]
    case = run_case(tmp_path, inventory(certs, [svc("tls@.service", "t.example.internal", "c")], ["R"]))
    override = "systemd/system/tls@.service.d/override.conf"
    assert override in case.produced
    sections, directives = kit.parse_override(case.produced[override].decode())
    assert sections == ["Service"]
    assert directives["Service.ExecStart"] == ["", "/bin/false"]
    assert_parity(case)


def test_nginx_snippet_points_at_replacement(tmp_path: Path) -> None:
    """A rotation snippet references the replacement certificate by its fp-hex."""
    certs = base_pki() + [
        leaf("old", "o1", "I", ["n.example.internal"], na=EXPIRED_NA),
        leaf("new", "n1", "I", ["n.example.internal"], na=FRESH_NA),
    ]
    case = run_case(tmp_path, inventory(certs, [svc("n.service", "n.example.internal", "old")], ["R"]))
    fields = kit.parse_nginx(case.produced["nginx/snippets/n.service.conf"].decode())
    fphex = kit.fp_hex(certs[3])
    assert fields["ssl_certificate"] == f"/etc/certguard/certs/{fphex}.pem"
    assert fields["ssl_certificate_key"] == f"/etc/certguard/private/{fphex}.key"
    assert_parity(case)


def test_audit_markdown_matches_reference(tmp_path: Path) -> None:
    """The Markdown audit note matches the independently rendered note."""
    certs = base_pki() + [
        leaf("old", "o1", "I", ["w.example.internal"], na=EXPIRED_NA),
        leaf("new", "n1", "I", ["w.example.internal"], na=FRESH_NA),
        leaf("ok", "k1", "I", ["ok.example.internal"], na=FRESH_NA),
    ]
    services = [
        svc("w.service", "w.example.internal", "old"),
        svc("ok.service", "ok.example.internal", "ok"),
        svc("blk.service", "blk.example.internal", "absent"),
    ]
    case = run_case(tmp_path, inventory(certs, services, ["R"]))
    note = kit.parse_audit_md(case.produced["tls-rotation-audit.md"].decode())
    assert note["summary"]["Evaluated at"] == T
    assert [s["unit"] for s in note["sections"]] == ["blk.service", "ok.service", "w.service"]
    decisions = {s["unit"]: dict(s["fields"])["Decision"] for s in note["sections"]}
    assert decisions["ok.service"] == "COMPLIANT"
    assert decisions["blk.service"] == "BLOCKED (missing)"
    assert decisions["w.service"].startswith("ROTATED to ")
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Revocation query set
# --------------------------------------------------------------------------- #
def test_revocation_service_is_consulted(tmp_path: Path) -> None:
    """The tool reaches its revocation decision by querying the CRL service (the API is
    not bypassed): the issuer of a revoked leaf appears among the queried issuers."""
    lf = leaf("c", "c1", "I", ["m.example.internal"], serial="900")   # decimal on the cert
    crls = crl("I", [{"serial": "0x384", "reason": "keyCompromise"}])   # hex on the CRL, same value
    case = run_case(tmp_path, inventory(base_pki() + [lf], [svc("m.service", "m.example.internal", "c")], ["R"]), crls)
    assert case.decision("m.service")["reason"] == "revoked"
    assert "I" in case.queried, "the revoked certificate's issuer CRL must be fetched"
    assert case.queried, "the tool must consult the revocation service"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Anti-cheat
# --------------------------------------------------------------------------- #
def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    """The same inputs always produce the same output bytes."""
    certs = base_pki() + [
        leaf("old", "o1", "I", ["w.example.internal"], na=EXPIRED_NA),
        leaf("new", "n1", "I", ["w.example.internal"], na=FRESH_NA),
    ]
    inv = inventory(certs, [svc("w.service", "w.example.internal", "old")], ["R"])
    first = run_case(tmp_path / "one", inv)
    second = run_case(tmp_path / "two", inv)
    assert first.produced == second.produced


def test_semantic_change_changes_the_report(tmp_path: Path) -> None:
    """Changing a replacement's expiry changes the selected certificate and the report bytes."""
    def build(late_na):
        return base_pki() + [
            leaf("old", "o1", "I", ["w.example.internal"], na=EXPIRED_NA, serial="1"),
            leaf("a", "a1", "I", ["w.example.internal"], na="2027-01-01T00:00:00Z", serial="2"),
            leaf("b", "b1", "I", ["w.example.internal"], na=late_na, serial="3"),
        ]
    svcs = [svc("w.service", "w.example.internal", "old")]
    first = run_case(tmp_path / "a", inventory(build("2026-12-01T00:00:00Z"), svcs, ["R"]))
    second = run_case(tmp_path / "b", inventory(build("2028-12-01T00:00:00Z"), svcs, ["R"]))
    assert first.produced["tls-trust-report.json"] != second.produced["tls-trust-report.json"]


# --------------------------------------------------------------------------- #
# Generated inventories
# --------------------------------------------------------------------------- #
def test_generated_inventories_match_reference_oracle(tmp_path: Path) -> None:
    """Deterministically generated inventories must match the independent oracle byte for byte."""
    seen: set[str] = set()
    for seed in range(20):
        rng = random.Random(0xCE47 + seed)
        inv_data, crls = kit.generate_inventory(rng)
        case = run_case(tmp_path / f"h{seed}", inv_data, crls)
        assert_parity(case)
        for row in case.rows:
            seen.add(f"{row['decision']}:{row['reason']}")
    required = {
        "ok:compliant", "rotate:expiring", "rotate:expired", "rotate:revoked",
        "rotate:untrusted", "rotate:missing", "block:untrusted",
    }
    assert required <= seen, f"missing branches: {required - seen}"


# --------------------------------------------------------------------------- #
# Default configuration
# --------------------------------------------------------------------------- #
def _port_is_free(port: int) -> bool:
    """Whether 127.0.0.1:<port> can be bound right now."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _wait_port_free(port: int, timeout: float = 5.0) -> None:
    """Poll until the port is bindable, up to a bounded timeout."""
    deadline = time.monotonic() + timeout
    while not _port_is_free(port) and time.monotonic() < deadline:
        time.sleep(0.05)


def _free_default_port() -> None:
    """Terminate any leftover listener on 127.0.0.1:8730 (the agent may have left
    the shipped CRL mirror running) and wait, with bounded polling, for the port
    to become bindable again."""
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
    _wait_port_free(8730)


def test_default_configuration_paths(tmp_path: Path) -> None:
    """With no overrides the tool reads /app/data/inventory, queries the CRL service
    at 127.0.0.1:8730, and writes under /app/out."""
    if APP != Path("/app"):
        pytest.skip("default paths are container-absolute; only exercised in the container")
    inv_dir = APP / "data" / "inventory"
    assert (inv_dir / "certificates.json").is_file(), "the inventory must remain at /app/data/inventory"

    inv_data = {
        "certificates": json.loads((inv_dir / "certificates.json").read_text()),
        "services": json.loads((inv_dir / "services.json").read_text()),
        "trust_store": json.loads((inv_dir / "trust-store.json").read_text()),
        "policy": json.loads((inv_dir / "policy.json").read_text()),
    }
    crls: dict = {}
    crl_dir = APP / "vendor-crl"
    if crl_dir.is_dir():
        for path in crl_dir.glob("*.json"):
            crls[path.stem] = json.loads(path.read_text())

    inv = kit.Inventory(inv_data)
    expected = kit.build_oracle(inv, crls)

    out_dir = APP / "out"
    shutil.rmtree(out_dir, ignore_errors=True)
    _free_default_port()
    with kit.RevocationServer(crls, port=8730) as server:
        env = os.environ.copy()
        for name in ("INVENTORY_DIR", "REVOCATION_API_BASE", "OUTPUT_DIR"):
            env.pop(name, None)
        result = subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=60)
        queried = sorted(set(server.queried))
    assert result.returncode == 0, f"tool failed on defaults: {result.stdout}\n{result.stderr}"
    assert queried == sorted(kit.expected_queries(inv)), (
        f"CRL query set on defaults differs; expected {sorted(kit.expected_queries(inv))}, got {queried}"
    )
    assert_artifacts_match(_collect(out_dir), expected)
    shutil.rmtree(out_dir, ignore_errors=True)

"""Black-box verifier for the mailguard email-authentication hardening tool.

The verifier never imports the tool. It mints estates (scope, hardening config,
observed connecting IPs, a DNS zone database and a spoof-intel feed), serves the
resolver and the feed from mock HTTP servers, runs the compiled command, and
compares every produced artifact against an independent Python oracle.
Deterministically generated estates make fixture-specific or hard-coded solutions
insufficient.
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

import mail_kit as kit
import pytest

APP = Path(os.environ.get("APP_DIR", "/app"))
DEFAULT_DNS_PORT = 8785
DEFAULT_FEED_PORT = 8786
DEFAULT_CONFIG = {"rua": "mailto:agg@sec.example", "policy": "reject", "spf_all": "-all"}


def _cli() -> list[str]:
    js = os.environ.get("MAILGUARD_JS")
    if js:
        return ["node", js]
    return [str(APP / "bin" / "mailguard")]


CLI = _cli()


def _collect(out_dir: Path) -> dict[str, bytes]:
    produced: dict[str, bytes] = {}
    for path in out_dir.rglob("*"):
        if path.is_file():
            produced[str(path.relative_to(out_dir)).replace(os.sep, "/")] = path.read_bytes()
    return produced


class Case:
    def __init__(self, produced, expected, report, queried):
        self.produced = produced
        self.expected = expected
        self.report = report
        self.queried = queried

    def obs(self, oid: str) -> dict:
        for o in self.report["observations"]:
            if o["id"] == oid:
                return o
        raise KeyError(oid)

    def domain(self, name: str) -> dict:
        for d in self.report["domains"]:
            if d["domain"] == name:
                return d
        raise KeyError(name)


def run_case(base_dir: Path, scope: dict, zones: dict, probes: list, feed: list, config: dict | None = None) -> Case:
    config = config or DEFAULT_CONFIG
    base_dir.mkdir(parents=True, exist_ok=True)
    in_dir = base_dir / "in"
    out_dir = base_dir / "out"
    sp, pp, cp = kit.write_inputs(str(in_dir), scope, {"probes": probes}, config)
    expected = kit.build_oracle(scope, config, zones, probes, feed)
    with kit.DnsServer(zones) as dns, kit.FeedServer(feed) as feed_server:
        env = os.environ.copy()
        env["SCOPE_PATH"] = sp
        env["PROBES_PATH"] = pp
        env["POLICY_PATH"] = cp
        env["DNS_API_BASE"] = f"http://127.0.0.1:{dns.port}"
        env["FEED_API_BASE"] = f"http://127.0.0.1:{feed_server.port}"
        env["OUTPUT_DIR"] = str(out_dir)
        result = subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=120, check=False)
        queried = list(dns.queried)
    assert result.returncode == 0, f"tool failed: {result.stdout}\n{result.stderr}"
    produced = _collect(out_dir)
    report = json.loads(produced["email-auth-report.json"])
    return Case(produced, expected, report, queried)


def assert_parity(case: Case) -> None:
    assert set(case.produced) == set(case.expected), (
        f"file set mismatch; missing={sorted(set(case.expected) - set(case.produced))} "
        f"extra={sorted(set(case.produced) - set(case.expected))}"
    )
    for name, data in case.expected.items():
        assert case.produced[name] == data, f"bytes differ for {name}"


def probe(oid: str, domain: str, ip: str) -> dict:
    return {"id": oid, "domain": domain, "ip": ip}


@pytest.fixture(scope="session", autouse=True)
def _built_tool() -> None:
    """The compiled entry point must exist before any case runs."""
    if os.environ.get("MAILGUARD_JS"):
        return
    assert (APP / "bin" / "mailguard").is_file(), f"missing compiled tool at {APP / 'bin' / 'mailguard'}"


# --------------------------------------------------------------------------- #
# check-host walk: short-circuit, include semantics, budgets
# --------------------------------------------------------------------------- #
def test_short_circuit_stops_at_first_match(tmp_path: Path) -> None:
    """A matching ip4 mechanism returns Pass immediately; the later include that would
    add DNS lookups is never reached, so lookups stays zero."""
    zones = {
        "s.example": {"TXT": ["v=spf1 ip4:100.64.0.0/24 include:inc.s.example -all"]},
        "inc.s.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
    }
    probes = [probe("t1", "s.example", "100.64.0.9")]
    case = run_case(tmp_path, {"domains": ["s.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass"
    assert case.obs("t1")["lookups"] == 0
    assert_parity(case)


def test_include_returns_pass_not_membership(tmp_path: Path) -> None:
    """An include contributes only when it evaluates to Pass. An IP inside the
    includer's own ip4 (but not the include's) still passes via the later mechanism,
    because the include yields Fail (its -all) which is a No-Match, not a rejection."""
    zones = {
        "i.example": {"TXT": ["v=spf1 include:inc.i.example ip4:100.64.5.0/24 ~all"]},
        "inc.i.example": {"TXT": ["v=spf1 ip4:198.51.100.0/24 -all"]},
    }
    probes = [
        probe("t1", "i.example", "198.51.100.7"),  # matches include -> pass
        probe("t2", "i.example", "100.64.5.7"),    # include Fails (no match) -> continue -> ip4 pass
        probe("t3", "i.example", "10.9.9.9"),      # nothing matches -> ~all softfail
    ]
    case = run_case(tmp_path, {"domains": ["i.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass"
    assert case.obs("t2")["spf_result"] == "pass"
    assert case.obs("t3")["spf_result"] == "softfail"
    assert_parity(case)


def test_include_of_missing_record_is_permerror(tmp_path: Path) -> None:
    """Including a domain that publishes no SPF record is a PermError."""
    zones = {"p.example": {"TXT": ["v=spf1 include:nope.p.example -all"]}}
    probes = [probe("t1", "p.example", "10.0.0.1")]
    case = run_case(tmp_path, {"domains": ["p.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "permerror"
    assert_parity(case)


def test_lookup_limit_permerror_is_ip_dependent(tmp_path: Path) -> None:
    """The 10-lookup limit is counted along the evaluated path: an IP that matches the
    first mechanism passes with no lookups, while an IP that forces the walk past ten
    includes PermErrors — same record, different result."""
    zones = {}
    includes = []
    for k in range(11):
        name = f"c{k}.o.example"
        includes.append(f"include:{name}")
        zones[name] = {"TXT": [f"v=spf1 ip4:203.0.200.{k}/32 -all"]}
    zones["o.example"] = {"TXT": ["v=spf1 ip4:100.64.0.0/24 " + " ".join(includes) + " ~all"]}
    probes = [
        probe("t1", "o.example", "100.64.0.5"),  # first ip4 matches -> pass, 0 lookups
        probe("t2", "o.example", "10.1.2.3"),    # walks the includes -> permerror
    ]
    case = run_case(tmp_path, {"domains": ["o.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass"
    assert case.obs("t1")["lookups"] == 0
    assert case.obs("t2")["spf_result"] == "permerror"
    assert case.obs("t2")["lookups"] == 11
    assert "spf_permerror_observed" in case.domain("o.example")["spf"]["weaknesses"]
    assert_parity(case)


def test_void_limit_permerror(tmp_path: Path) -> None:
    """More than two lookups that resolve to nothing PermError."""
    record = "v=spf1 exists:%{ir}.a.v.example exists:%{ir}.b.v.example exists:%{ir}.c.v.example ~all"
    zones = {"v.example": {"TXT": [record]}}
    probes = [probe("t1", "v.example", "10.0.0.1")]
    case = run_case(tmp_path, {"domains": ["v.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "permerror"
    assert_parity(case)


def test_macro_exists_reversed_ip(tmp_path: Path) -> None:
    """A `%{ir}` exists check reverses the connecting IP's labels; the allow-list entry
    for that reversed IP makes it Pass."""
    zones = {
        "m.example": {"TXT": ["v=spf1 exists:%{ir}.allow.m.example -all"]},
        "4.3.2.1.allow.m.example": {"A": ["127.0.0.2"]},
    }
    probes = [
        probe("t1", "m.example", "1.2.3.4"),  # reversed 4.3.2.1 present -> pass
        probe("t2", "m.example", "9.9.9.9"),  # reversed absent -> fail (-all)
    ]
    case = run_case(tmp_path, {"domains": ["m.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass"
    assert case.obs("t2")["spf_result"] == "fail"
    assert_parity(case)


def test_a_and_mx_match(tmp_path: Path) -> None:
    """`a` and `mx` match when the connecting IP is one of the resolved addresses."""
    zones = {
        "am.example": {"TXT": ["v=spf1 a mx -all"], "A": ["100.64.7.7"], "MX": ["mail.am.example"]},
        "mail.am.example": {"A": ["100.64.8.8"]},
    }
    probes = [
        probe("t1", "am.example", "100.64.7.7"),  # a match, lookups 1
        probe("t2", "am.example", "100.64.8.8"),  # mx match, lookups 2
        probe("t3", "am.example", "10.0.0.1"),    # fail
    ]
    case = run_case(tmp_path, {"domains": ["am.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass" and case.obs("t1")["lookups"] == 1
    assert case.obs("t2")["spf_result"] == "pass" and case.obs("t2")["lookups"] == 2
    assert case.obs("t3")["spf_result"] == "fail"
    assert_parity(case)


def test_redirect_supplies_result(tmp_path: Path) -> None:
    """With no matching mechanism and no `all`, a redirect's target governs the result."""
    zones = {
        "r.example": {"TXT": ["v=spf1 ip4:100.64.5.0/24 redirect=red.example"]},
        "red.example": {"TXT": ["v=spf1 ip4:100.64.6.0/24 ~all"]},
    }
    probes = [
        probe("t1", "r.example", "100.64.6.9"),  # matches redirect ip4 -> pass
        probe("t2", "r.example", "10.0.0.1"),    # redirect ~all -> softfail
    ]
    case = run_case(tmp_path, {"domains": ["r.example"]}, zones, probes, [])
    assert case.obs("t1")["spf_result"] == "pass"
    assert case.obs("t2")["spf_result"] == "softfail"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Static analysis + hardening
# --------------------------------------------------------------------------- #
def test_effective_all_and_ptr_weaknesses(tmp_path: Path) -> None:
    """The published record's `+all` and `ptr` raise the permissive and deprecated
    weaknesses, and a `+all` record passes an unrelated IP."""
    zones = {"l.example": {"TXT": ["v=spf1 a ptr +all"], "A": ["192.0.2.50"]}}
    probes = [probe("t1", "l.example", "8.8.8.8")]
    case = run_case(tmp_path, {"domains": ["l.example"]}, zones, probes, [])
    spf = case.domain("l.example")["spf"]
    assert spf["effective_all"] == "pass"
    assert {"spf_permissive_all", "spf_deprecated_ptr"} <= set(spf["weaknesses"])
    assert case.obs("t1")["spf_result"] == "pass"
    assert_parity(case)


def test_hardened_spf_is_passing_ips_minus_flagged(tmp_path: Path) -> None:
    """The hardened record lists exactly the passing IPs as /32 ranges, dropping any
    that overlap a flagged feed source and raising spf_flagged_source."""
    zones = {"h.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 ip4:100.64.0.0/24 -all"]}}
    probes = [
        probe("t1", "h.example", "203.0.113.9"),  # passes but flagged -> removed
        probe("t2", "h.example", "100.64.0.9"),   # passes, kept
        probe("t3", "h.example", "10.0.0.1"),     # fail
    ]
    feed = [{"cidr": "203.0.113.0/24", "reason": "botnet"}]
    case = run_case(tmp_path, {"domains": ["h.example"]}, zones, probes, feed)
    spf = case.domain("h.example")["spf"]
    assert spf["hardened_record"] == "v=spf1 ip4:100.64.0.9/32 -all"
    assert "spf_flagged_source" in spf["weaknesses"]
    assert_parity(case)


def test_spf_missing(tmp_path: Path) -> None:
    """A domain with no SPF record is flagged and probes resolve to none."""
    zones = {"n.example": {"TXT": ["unrelated"]}}
    probes = [probe("t1", "n.example", "10.0.0.1")]
    case = run_case(tmp_path, {"domains": ["n.example"]}, zones, probes, [])
    assert case.domain("n.example")["spf"]["weaknesses"] == ["spf_missing"]
    assert case.obs("t1")["spf_result"] == "none"
    assert_parity(case)


def test_multiple_spf_records(tmp_path: Path) -> None:
    """More than one v=spf1 TXT raises spf_multiple_records."""
    zones = {"dup.example": {"TXT": ["v=spf1 ip4:100.64.0.0/24 -all", "v=spf1 ip4:100.64.1.0/24 ~all"]}}
    probes = [probe("t1", "dup.example", "100.64.0.9")]
    case = run_case(tmp_path, {"domains": ["dup.example"]}, zones, probes, [])
    assert "spf_multiple_records" in case.domain("dup.example")["spf"]["weaknesses"]
    assert_parity(case)


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #
def test_dmarc_weakness_codes(tmp_path: Path) -> None:
    """Quarantine policy, a weak explicit subdomain policy, partial pct and relaxed
    alignment each raise their code."""
    zones = {
        "dm.example": {"TXT": ["v=spf1 -all"]},
        "_dmarc.dm.example": {"TXT": ["v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:x@dm.example"]},
    }
    probes = [probe("t1", "dm.example", "10.0.0.1")]
    case = run_case(tmp_path, {"domains": ["dm.example"]}, zones, probes, [])
    weak = set(case.domain("dm.example")["dmarc"]["weaknesses"])
    assert {"dmarc_policy_quarantine", "dmarc_subdomain_gap", "dmarc_partial_pct", "dmarc_relaxed_alignment"} <= weak
    assert "dmarc_rua_missing" not in weak
    assert_parity(case)


def test_dmarc_missing_and_hardened_record(tmp_path: Path) -> None:
    """A domain with no _dmarc is flagged; the hardened DMARC is the strict template."""
    zones = {"dh.example": {"TXT": ["v=spf1 -all"]}}
    probes = [probe("t1", "dh.example", "10.0.0.1")]
    case = run_case(tmp_path, {"domains": ["dh.example"]}, zones, probes, [])
    d = case.domain("dh.example")["dmarc"]
    assert d["weaknesses"] == ["dmarc_missing"]
    assert case.produced["zones/dh.example/dmarc.txt"] == \
        b"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:agg@sec.example\n"
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Report shape, layout, query discipline
# --------------------------------------------------------------------------- #
def test_report_is_canonical_json(tmp_path: Path) -> None:
    """The report is canonical JSON: recursively key-sorted with one trailing newline."""
    zones = {"j.example": {"TXT": ["v=spf1 ip4:100.64.0.0/24 -all"]}}
    probes = [probe("t1", "j.example", "100.64.0.9")]
    case = run_case(tmp_path, {"domains": ["j.example"]}, zones, probes, [])
    body = case.produced["email-auth-report.json"]
    assert body.endswith(b"\n") and not body.endswith(b"\n\n")
    assert body == kit.canonical_json(json.loads(body))
    assert_parity(case)


def test_zone_files_and_audit_layout(tmp_path: Path) -> None:
    """Each domain gets zones/<domain>/spf.txt and dmarc.txt, plus the audit note."""
    zones = {"z.example": {"TXT": ["v=spf1 ip4:100.64.0.0/24 -all"]}}
    probes = [probe("t1", "z.example", "100.64.0.9")]
    case = run_case(tmp_path, {"domains": ["z.example"]}, zones, probes, [])
    assert "zones/z.example/spf.txt" in case.produced
    assert "zones/z.example/dmarc.txt" in case.produced
    assert case.produced["email-auth-audit.md"].startswith(b"# Email authentication hardening audit\n")
    assert_parity(case)


def test_resolver_queried_for_spf_and_dmarc(tmp_path: Path) -> None:
    """The tool resolves the domain's SPF TXT and its _dmarc TXT."""
    zones = {"q.example": {"TXT": ["v=spf1 ip4:100.64.0.0/24 -all"]}}
    probes = [probe("t1", "q.example", "100.64.0.9")]
    case = run_case(tmp_path, {"domains": ["q.example"]}, zones, probes, [])
    assert ("q.example", "TXT") in case.queried
    assert ("_dmarc.q.example", "TXT") in case.queried
    assert_parity(case)


# --------------------------------------------------------------------------- #
# Anti-cheat
# --------------------------------------------------------------------------- #
def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    """The same inputs always produce the same output bytes."""
    zones = {"s.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 ip4:100.64.0.0/24 -all"]}}
    probes = [probe("t1", "s.example", "203.0.113.9"), probe("t2", "s.example", "100.64.0.9")]
    feed = [{"cidr": "203.0.113.0/24", "reason": "botnet"}]
    first = run_case(tmp_path / "one", {"domains": ["s.example"]}, zones, probes, feed)
    second = run_case(tmp_path / "two", {"domains": ["s.example"]}, zones, probes, feed)
    assert first.produced == second.produced


def test_flagging_a_source_changes_bytes(tmp_path: Path) -> None:
    """Flagging a passing source changes the hardened record bytes."""
    zones = {"g.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 ip4:100.64.0.0/24 -all"]}}
    probes = [probe("t1", "g.example", "203.0.113.9"), probe("t2", "g.example", "100.64.0.9")]
    clean = run_case(tmp_path / "c", {"domains": ["g.example"]}, zones, probes, [])
    flagged = run_case(tmp_path / "f", {"domains": ["g.example"]}, zones, probes, [{"cidr": "203.0.113.0/24", "reason": "x"}])
    assert clean.produced["zones/g.example/spf.txt"] != flagged.produced["zones/g.example/spf.txt"]


# --------------------------------------------------------------------------- #
# Generated estates
# --------------------------------------------------------------------------- #
def test_generated_estates_match_reference_oracle(tmp_path: Path) -> None:
    """Deterministically generated estates must match the independent oracle byte for
    byte, and collectively exercise every SPF result and weakness code."""
    seen_result: set[str] = set()
    seen_spf: set[str] = set()
    seen_dmarc: set[str] = set()
    for seed in range(24):
        rng = random.Random(0x5A17 + seed)
        scope, config, zones, probes_wrap, feed = kit.generate_estate(rng)
        case = run_case(tmp_path / f"g{seed}", scope, zones, probes_wrap["probes"], feed, config)
        assert_parity(case)
        for o in case.report["observations"]:
            seen_result.add(o["spf_result"])
        for d in case.report["domains"]:
            seen_spf.update(d["spf"]["weaknesses"])
            seen_dmarc.update(d["dmarc"]["weaknesses"])
    assert {"pass", "fail", "softfail", "neutral", "none", "permerror"} <= seen_result, seen_result
    required_spf = {"spf_missing", "spf_permissive_all", "spf_neutral_all", "spf_softfail",
                    "spf_no_all", "spf_deprecated_ptr", "spf_permerror_observed", "spf_flagged_source"}
    required_dmarc = {"dmarc_missing", "dmarc_policy_none", "dmarc_policy_quarantine",
                      "dmarc_subdomain_gap", "dmarc_partial_pct", "dmarc_relaxed_alignment", "dmarc_rua_missing"}
    assert required_spf <= seen_spf, f"missing SPF coverage: {required_spf - seen_spf}"
    assert required_dmarc <= seen_dmarc, f"missing DMARC coverage: {required_dmarc - seen_dmarc}"


# --------------------------------------------------------------------------- #
# Default configuration
# --------------------------------------------------------------------------- #
def _port_is_free(port: int) -> bool:
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe_sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    else:
        return True
    finally:
        probe_sock.close()


def _free_port(port: int) -> None:
    hex_port = f":{port:04X}"
    inodes: set[str] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(table).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            parts = row.split()
            if len(parts) > 9 and parts[1].endswith(hex_port) and parts[3] == "0A":
                inodes.add(parts[9])
    if inodes:
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
    deadline = time.monotonic() + 5.0
    while not _port_is_free(port) and time.monotonic() < deadline:
        time.sleep(0.05)


def test_default_configuration_paths() -> None:
    """With no overrides the tool reads /app/data, resolves at 127.0.0.1:8785, queries
    the feed at 127.0.0.1:8786, and writes under /app/out."""
    if os.environ.get("MAILGUARD_JS") or Path("/app") != APP:
        pytest.skip("default paths are container-absolute; only exercised in the container")
    data = APP / "data"
    scope = json.loads((data / "scope.json").read_text())
    probes = json.loads((data / "probes.json").read_text())["probes"]
    config = json.loads((data / "config.json").read_text())
    zones = json.loads((data / "zones.json").read_text())
    feed = json.loads((data / "feed.json").read_text())["sources"]
    expected = kit.build_oracle(scope, config, zones, probes, feed)

    out_dir = APP / "out"
    shutil.rmtree(out_dir, ignore_errors=True)
    _free_port(DEFAULT_DNS_PORT)
    _free_port(DEFAULT_FEED_PORT)
    with kit.DnsServer(zones, port=DEFAULT_DNS_PORT) as dns, kit.FeedServer(feed, port=DEFAULT_FEED_PORT) as feed_server:
        assert dns.port == DEFAULT_DNS_PORT and feed_server.port == DEFAULT_FEED_PORT
        env = os.environ.copy()
        for name in ("SCOPE_PATH", "PROBES_PATH", "POLICY_PATH", "DNS_API_BASE", "FEED_API_BASE", "OUTPUT_DIR"):
            env.pop(name, None)
        result = subprocess.run(CLI, env=env, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, f"tool failed on defaults: {result.stdout}\n{result.stderr}"
    produced = _collect(out_dir)
    assert set(produced) == set(expected)
    for name, data_bytes in expected.items():
        assert produced[name] == data_bytes, f"bytes differ for {name}"
    shutil.rmtree(out_dir, ignore_errors=True)

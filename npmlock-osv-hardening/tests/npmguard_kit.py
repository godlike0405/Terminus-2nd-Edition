"""Independent oracle and fixtures for the npmguard verifier.

Nothing here imports the tool under test. The kit re-implements Semantic
Versioning precedence and npm range satisfaction, OSV SEMVER range containment,
the remediation decision policy, canonical JSON and the exact artifact byte
layout in Python, mints npm lockfiles / registry snapshots / advisory sets, and
serves the advisories over an OSV-compatible mock so the tool's output can be
compared against a from-scratch reference.
"""

from __future__ import annotations

import json
import re
import threading
from functools import cmp_to_key
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# --------------------------------------------------------------------------- #
# Semantic Versioning precedence
# --------------------------------------------------------------------------- #
_CORE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _parse_prerelease(text: str | None) -> list:
    if not text:
        return []
    return [int(part) if part.isdigit() else part for part in text.split(".")]


def parse(version: str) -> dict:
    match = _CORE.match(version.strip())
    if match is None:
        raise ValueError(f"invalid semantic version: {version}")
    return {
        "major": int(match.group(1)),
        "minor": int(match.group(2)),
        "patch": int(match.group(3)),
        "prerelease": _parse_prerelease(match.group(4)),
    }


def _compare_identifiers(a, b) -> int:
    a_num, b_num = isinstance(a, int), isinstance(b, int)
    if a_num and b_num:
        return -1 if a < b else (1 if a > b else 0)
    if a_num:
        return -1
    if b_num:
        return 1
    return -1 if a < b else (1 if a > b else 0)


def _compare_prerelease(a: list, b: list) -> int:
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for x, y in zip(a, b):
        diff = _compare_identifiers(x, y)
        if diff != 0:
            return diff
    return -1 if len(a) < len(b) else (1 if len(a) > len(b) else 0)


def compare(left: dict, right: dict) -> int:
    for key in ("major", "minor", "patch"):
        if left[key] != right[key]:
            return -1 if left[key] < right[key] else 1
    return _compare_prerelease(left["prerelease"], right["prerelease"])


def compare_versions(left: str, right: str) -> int:
    return compare(parse(left), parse(right))


# --------------------------------------------------------------------------- #
# npm range satisfaction
# --------------------------------------------------------------------------- #
def _ver(major, minor, patch, prerelease=None) -> dict:
    return {"major": major, "minor": minor, "patch": patch, "prerelease": prerelease or []}


_ANY = {"any": True, "op": "=", "ver": _ver(0, 0, 0)}


def _comparator(op: str, v: dict) -> dict:
    return {"any": False, "op": op, "ver": v}


def _xr(component: str):
    if component in ("", "*", "x", "X"):
        return None
    return int(component)


def _parse_partial(text: str) -> dict:
    core = text
    prerelease: list = []
    plus = core.find("+")
    if plus >= 0:
        core = core[:plus]
    dash = core.find("-")
    if dash >= 0:
        prerelease = _parse_prerelease(core[dash + 1:])
        core = core[:dash]
    parts = core.split(".")
    return {
        "major": _xr(parts[0] if len(parts) > 0 else ""),
        "minor": _xr(parts[1] if len(parts) > 1 else ""),
        "patch": _xr(parts[2] if len(parts) > 2 else ""),
        "prerelease": prerelease,
    }


def _caret(text: str) -> list:
    p = _parse_partial(text)
    if p["major"] is None:
        return [_ANY]
    low = _comparator(">=", _ver(p["major"], p["minor"] or 0, p["patch"] or 0,
                                 p["prerelease"] if p["patch"] is not None else []))
    if p["major"] != 0:
        high = _comparator("<", _ver(p["major"] + 1, 0, 0))
    elif p["minor"] is None:
        high = _comparator("<", _ver(1, 0, 0))
    elif p["minor"] != 0:
        high = _comparator("<", _ver(0, p["minor"] + 1, 0))
    elif p["patch"] is None:
        high = _comparator("<", _ver(0, 1, 0))
    else:
        high = _comparator("<", _ver(0, 0, p["patch"] + 1))
    return [low, high]


def _tilde(text: str) -> list:
    p = _parse_partial(text)
    if p["major"] is None:
        return [_ANY]
    low = _comparator(">=", _ver(p["major"], p["minor"] or 0, p["patch"] or 0,
                                 p["prerelease"] if p["patch"] is not None else []))
    if p["minor"] is None:
        high = _comparator("<", _ver(p["major"] + 1, 0, 0))
    else:
        high = _comparator("<", _ver(p["major"], p["minor"] + 1, 0))
    return [low, high]


def _xrange(op: str, text: str) -> list:
    p = _parse_partial(text)
    if p["major"] is None:
        if op in ("=", ">=", "<="):
            return [_ANY]
        return [_comparator(op, _ver(0, 0, 0))]
    if p["minor"] is None:
        if op == "=":
            return [_comparator(">=", _ver(p["major"], 0, 0)), _comparator("<", _ver(p["major"] + 1, 0, 0))]
        if op == ">":
            return [_comparator(">=", _ver(p["major"] + 1, 0, 0))]
        if op == "<=":
            return [_comparator("<", _ver(p["major"] + 1, 0, 0))]
        return [_comparator(op, _ver(p["major"], 0, 0))]
    if p["patch"] is None:
        if op == "=":
            return [_comparator(">=", _ver(p["major"], p["minor"], 0)),
                    _comparator("<", _ver(p["major"], p["minor"] + 1, 0))]
        if op == ">":
            return [_comparator(">=", _ver(p["major"], p["minor"] + 1, 0))]
        if op == "<=":
            return [_comparator("<", _ver(p["major"], p["minor"] + 1, 0))]
        return [_comparator(op, _ver(p["major"], p["minor"], 0))]
    return [_comparator(op, _ver(p["major"], p["minor"], p["patch"], p["prerelease"]))]


def _hyphen(lower: str, upper: str) -> list:
    low = _parse_partial(lower)
    high = _parse_partial(upper)
    low_cmp = _comparator(">=", _ver(low["major"] or 0, low["minor"] or 0, low["patch"] or 0, low["prerelease"]))
    if high["minor"] is None:
        high_cmp = _comparator("<", _ver((high["major"] or 0) + 1, 0, 0))
    elif high["patch"] is None:
        high_cmp = _comparator("<", _ver(high["major"] or 0, high["minor"] + 1, 0))
    else:
        high_cmp = _comparator("<=", _ver(high["major"], high["minor"], high["patch"], high["prerelease"]))
    return [low_cmp, high_cmp]


def _parse_comparator_set(text: str) -> list:
    trimmed = text.strip()
    if trimmed in ("", "*"):
        return [_ANY]
    tokens = re.split(r"\s+", trimmed)
    if len(tokens) == 3 and tokens[1] == "-":
        return _hyphen(tokens[0], tokens[2])
    comparators: list = []
    for token in tokens:
        if token == "":
            continue
        if token.startswith("^"):
            comparators += _caret(token[1:])
        elif token.startswith("~"):
            comparators += _tilde(token[1:])
        elif token.startswith(">="):
            comparators += _xrange(">=", token[2:])
        elif token.startswith("<="):
            comparators += _xrange("<=", token[2:])
        elif token.startswith(">"):
            comparators += _xrange(">", token[1:])
        elif token.startswith("<"):
            comparators += _xrange("<", token[1:])
        elif token.startswith("="):
            comparators += _xrange("=", token[1:])
        else:
            comparators += _xrange("=", token)
    return comparators or [_ANY]


def _test_comparator(c: dict, version: dict) -> bool:
    if c["any"]:
        return True
    cmp = compare(version, c["ver"])
    op = c["op"]
    if op == "=":
        return cmp == 0
    if op == ">":
        return cmp > 0
    if op == ">=":
        return cmp >= 0
    if op == "<":
        return cmp < 0
    return cmp <= 0


def _test_set(comparators: list, version: dict) -> bool:
    for c in comparators:
        if not _test_comparator(c, version):
            return False
    if version["prerelease"]:
        allowed = False
        for c in comparators:
            if c["any"]:
                continue
            v = c["ver"]
            if v["prerelease"] and v["major"] == version["major"] and v["minor"] == version["minor"] and v["patch"] == version["patch"]:
                allowed = True
        if not allowed:
            return False
    return True


def satisfies(version: str, range_text: str) -> bool:
    parsed = parse(version)
    for group in range_text.split("||"):
        if _test_set(_parse_comparator_set(group), parsed):
            return True
    return False


# --------------------------------------------------------------------------- #
# OSV containment
# --------------------------------------------------------------------------- #
def _intervals(events: list[dict]) -> list[tuple[str, str, str | None]]:
    intervals: list[tuple[str, str, str | None]] = []
    introduced: str | None = None
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        elif "fixed" in event:
            intervals.append((introduced if introduced is not None else "0.0.0", "fixed", event["fixed"]))
            introduced = None
        elif "last_affected" in event:
            intervals.append((introduced if introduced is not None else "0.0.0", "last_affected", event["last_affected"]))
            introduced = None
    if introduced is not None:
        intervals.append((introduced, "open", None))
    return intervals


def _range_hit(events: list[dict], version: str) -> tuple[bool, str | None]:
    for intro, kind, end in _intervals(events):
        lower = "0.0.0" if intro == "0" else intro
        if compare_versions(version, lower) < 0:
            continue
        if kind == "open":
            return True, None
        if kind == "fixed" and compare_versions(version, end) < 0:
            return True, end
        if kind == "last_affected" and compare_versions(version, end) <= 0:
            return True, None
    return False, None


def advisory_hit(vuln: dict, package: str, version: str) -> tuple[bool, str | None]:
    if "withdrawn" in vuln:
        return False, None
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package or pkg.get("ecosystem") != "npm":
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "SEMVER":
                continue
            hit, fixed = _range_hit(rng.get("events", []), version)
            if hit:
                return True, fixed
    return False, None


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #
def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- #
# Lockfile model
# --------------------------------------------------------------------------- #
def _name_from_path(key: str) -> str:
    marker = "node_modules/"
    index = key.rfind(marker)
    return key[index + len(marker):] if index >= 0 else key


def parse_lockfile(lockfile: dict) -> list[dict]:
    nodes = lockfile.get("packages", {})
    constraints: dict[str, set] = {}
    for node in nodes.values():
        for dep_name, rng in (node.get("dependencies") or {}).items():
            constraints.setdefault(dep_name, set()).add(rng)

    aggregate: dict[str, dict] = {}
    for key, node in nodes.items():
        if key == "" or node.get("version") is None:
            continue
        name = _name_from_path(key)
        entry = aggregate.setdefault(name, {"versions": [], "paths": [], "production": False})
        entry["versions"].append((node["version"], len(key.split("/")), key))
        entry["paths"].append(key)
        if node.get("dev") is not True and node.get("optional") is not True:
            entry["production"] = True

    packages = []
    for name, entry in aggregate.items():
        chosen = sorted(entry["versions"], key=lambda item: (item[1], item[2]))[0]
        packages.append({
            "name": name,
            "version": chosen[0],
            "paths": sorted(entry["paths"]),
            "production": entry["production"],
            "constraints": sorted(constraints.get(name, set())),
        })
    packages.sort(key=lambda pkg: pkg["name"])
    return packages


# --------------------------------------------------------------------------- #
# Decision policy
# --------------------------------------------------------------------------- #
def _unaffected_by_all(advisories: list[dict], name: str, version: str) -> bool:
    return not any(advisory_hit(vuln, name, version)[0] for vuln in advisories)


def decide(pkg: dict, advisories: list[dict], registry: list[str]) -> dict:
    base = {
        "name": pkg["name"],
        "installed_version": pkg["version"],
        "paths": pkg["paths"],
        "constraints": pkg["constraints"],
    }
    applicable = [vuln for vuln in advisories if advisory_hit(vuln, pkg["name"], pkg["version"])[0]]
    if not applicable:
        return {**base, "decision": "ok", "reason": "clean", "target_version": None,
                "max_severity": None, "advisories": []}
    ids = sorted(vuln["id"] for vuln in applicable)
    severity = max((vuln.get("database_specific", {}).get("severity", "LOW") for vuln in applicable),
                   key=SEVERITIES.index)
    higher_unaffected = [
        candidate for candidate in registry
        if compare_versions(candidate, pkg["version"]) > 0 and _unaffected_by_all(advisories, pkg["name"], candidate)
    ]
    satisfying = [
        candidate for candidate in higher_unaffected
        if all(satisfies(candidate, rng) for rng in pkg["constraints"])
    ]
    if satisfying:
        target = satisfying[0]
        for candidate in satisfying:
            if compare_versions(candidate, target) < 0:
                target = candidate
        return {**base, "decision": "upgrade", "reason": "vulnerable_fixable", "target_version": target,
                "max_severity": severity, "advisories": ids}
    reason = "no_safe_version" if higher_unaffected else "no_fix"
    return {**base, "decision": "block", "reason": reason, "target_version": None,
            "max_severity": severity, "advisories": ids}


def findings_for(lockfile: dict, registry: dict, advisories_by_pkg: dict) -> list[dict]:
    packages = [pkg for pkg in parse_lockfile(lockfile) if pkg["production"]]
    findings = []
    for pkg in packages:
        findings.append(decide(pkg, advisories_by_pkg.get(pkg["name"], []), registry.get(pkg["name"], [])))
    findings.sort(key=lambda finding: finding["name"])
    return findings


# --------------------------------------------------------------------------- #
# Artifact rendering
# --------------------------------------------------------------------------- #
def _block_filename(name: str) -> str:
    return name.replace("/", "__")


def _overrides(findings: list[dict]) -> dict:
    return {f["name"]: f["target_version"] for f in findings if f["decision"] == "upgrade"}


def render_markdown(findings: list[dict]) -> str:
    upgraded = sum(1 for f in findings if f["decision"] == "upgrade")
    blocked = sum(1 for f in findings if f["decision"] == "block")
    clean = sum(1 for f in findings if f["decision"] == "ok")
    lines = [
        "# npm dependency remediation audit",
        "",
        f"Packages audited: {len(findings)}",
        f"Upgraded: {upgraded}",
        f"Blocked: {blocked}",
        f"Clean: {clean}",
        "",
    ]
    for f in findings:
        if f["decision"] == "upgrade":
            verdict = f"UPGRADE to {f['target_version']}"
        elif f["decision"] == "block":
            verdict = f"BLOCKED ({f['reason']})"
        else:
            verdict = "CLEAN"
        advisories = ", ".join(f["advisories"]) if f["advisories"] else "none"
        constraints = ", ".join(f["constraints"]) if f["constraints"] else "none"
        lines += [
            f"## {f['name']}",
            "",
            f"- Installed: {f['installed_version']}",
            f"- Decision: {verdict}",
            f"- Advisories: {advisories}",
            f"- Constraints: {constraints}",
            "",
        ]
    return "\n".join(lines)


def build_oracle(lockfile: dict, registry: dict, advisories_by_pkg: dict) -> dict[str, bytes]:
    findings = findings_for(lockfile, registry, advisories_by_pkg)
    overrides = _overrides(findings)
    blocked = sorted(f["name"] for f in findings if f["decision"] == "block")
    report = {
        "generated_by": "npmguard",
        "report_version": "1",
        "packages": findings,
        "overrides": overrides,
        "blocked": blocked,
    }
    artifacts: dict[str, bytes] = {
        "remediation-report.json": canonical_json(report),
        "overrides.json": canonical_json({"overrides": overrides}),
    }
    for f in findings:
        if f["decision"] == "block":
            artifacts[f"blocks/{_block_filename(f['name'])}.deny"] = (
                f"Package: {f['name']}\nInstalled: {f['installed_version']}\n"
                f"Reason: {f['reason']}\nAction: manual-review\n".encode()
            )
    artifacts["remediation-audit.md"] = render_markdown(findings).encode()
    return artifacts


# --------------------------------------------------------------------------- #
# Artifact parsers (content and order strict; incidental whitespace tolerated)
# --------------------------------------------------------------------------- #
def parse_deny(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"not a block stanza field: {raw!r}")
        fields[name.strip()] = value.strip()
    return fields


def parse_audit_md(text: str) -> dict:
    if not text.endswith("\n"):
        raise ValueError("audit note must end with a newline")
    lines = [line.rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line != ""]
    if not lines or lines[0] != "# npm dependency remediation audit":
        raise ValueError("missing audit note title")
    summary: dict[str, int] = {}
    index = 1
    for label in ("Packages audited", "Upgraded", "Blocked", "Clean"):
        if index >= len(lines) or not lines[index].startswith(f"{label}:"):
            raise ValueError(f"missing summary line for {label}")
        summary[label] = int(lines[index].partition(":")[2].strip())
        index += 1
    sections: list[dict] = []
    current: dict | None = None
    for line in lines[index:]:
        if line.startswith("## "):
            current = {"name": line[3:].strip(), "fields": []}
            sections.append(current)
        elif line.startswith("- ") and current is not None:
            name, _, value = line[2:].partition(": ")
            current["fields"].append((name.strip(), value.strip()))
        else:
            raise ValueError(f"unexpected line in audit note: {line!r}")
    return {"summary": summary, "sections": sections}


# --------------------------------------------------------------------------- #
# OSV mock server
# --------------------------------------------------------------------------- #
class OsvServer:
    """Threaded OSV-compatible mock that records the packages it was queried for."""

    def __init__(self, advisories_by_pkg: dict[str, list[dict]], port: int = 0):
        self.queried: list[str] = []
        advisories = advisories_by_pkg
        queried = self.queried

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):  # noqa: N802
                if not self.path.startswith("/v1/query"):
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    name = json.loads(raw)["package"]["name"]
                except (ValueError, KeyError, TypeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                queried.append(name)
                payload = json.dumps({"vulns": advisories.get(name, [])}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> OsvServer:
        self._thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- #
# Deterministic project generator
# --------------------------------------------------------------------------- #
def _sorted_versions(versions: list[str]) -> list[str]:
    return sorted(set(versions), key=cmp_to_key(compare_versions))


def _pick_range(rng, major: int, installed: str) -> str:
    return rng.choice([f"^{installed}", f"^{major}.0.0", f"~{installed}", f"={installed}", f"{major}.x", f">={installed}"])


def _random_advisories(rng, index: int, name: str, major: int, versions: list[str]) -> list[dict]:
    releases = [v for v in versions if "-" not in v]
    vulns = []
    for j in range(rng.choice([0, 1, 1, 2])):
        style = rng.random()
        if style < 0.35:
            events = [{"introduced": rng.choice(["0", f"{major}.0.0"])}, {"fixed": rng.choice(releases)}]
        elif style < 0.55:
            events = [{"introduced": rng.choice(["0", f"{major}.0.0"])}]
        elif style < 0.75:
            events = [{"introduced": f"{major}.0.0"}, {"last_affected": rng.choice(releases)}]
        else:
            events = [{"introduced": "0"}, {"fixed": f"{major}.1.0"},
                      {"introduced": f"{major}.2.0"}, {"fixed": rng.choice(releases + [f"{major + 1}.0.0"])}]
        affected = [{"package": {"name": name, "ecosystem": "npm"},
                     "ranges": [{"type": "SEMVER", "events": events}]}]
        # Decoys that must be ignored: a non-SEMVER range beside the real one, a
        # foreign-ecosystem block, and an unrelated-package block.
        if rng.random() < 0.3:
            affected[0]["ranges"].insert(0, {"type": "GIT", "events": [{"introduced": "0"}]})
        if rng.random() < 0.3:
            affected.append({"package": {"name": name, "ecosystem": "PyPI"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]})
        if rng.random() < 0.3:
            affected.append({"package": {"name": f"other-{index}", "ecosystem": "npm"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]})
        vuln = {"id": f"OSV-{index:02d}{j:02d}", "affected": affected,
                "database_specific": {"severity": rng.choice(SEVERITIES)}}
        if rng.random() < 0.15:
            vuln["withdrawn"] = "2026-01-01T00:00:00Z"
        vulns.append(vuln)
    return vulns


def generate_project(rng) -> tuple[dict, dict, dict]:
    """Mint one randomized but self-consistent npm project, registry and advisory set."""
    count = rng.randrange(3, 7)
    specs = []
    for i in range(count):
        scoped = rng.random() < 0.3
        name = f"@s{i}/p{i}" if scoped else f"pkg{i}"
        major = rng.choice([1, 2, 3, 4])
        versions = [f"{major}.{minor}.0" for minor in range(rng.randrange(3, 6))]
        versions += [f"{major}.0.1", f"{major + 1}.0.0"]
        if rng.random() < 0.4:
            versions.append(f"{major}.{rng.randrange(1, 3)}.0-rc.1")
        versions = _sorted_versions(versions)
        installed = rng.choice([v for v in versions if "-" not in v])
        dev = rng.random() < 0.2
        specs.append({
            "name": name, "major": major, "versions": versions, "installed": installed,
            "dev": dev, "scoped": scoped,
            "root_range": _pick_range(rng, major, installed),
            "second_range": _pick_range(rng, major, installed) if rng.random() < 0.5 else None,
            "advisories": _random_advisories(rng, i, name, major, versions),
        })

    registry = {spec["name"]: spec["versions"] for spec in specs}
    advisories = {spec["name"]: spec["advisories"] for spec in specs}
    by_name = {spec["name"]: spec for spec in specs}

    root_deps: dict[str, str] = {}
    root_dev_deps: dict[str, str] = {}
    nodes: dict[str, dict] = {}

    # Pass 1 — one top-level node per package, and the root's own requirements.
    for spec in specs:
        node: dict = {"version": spec["installed"]}
        if spec["dev"]:
            node["dev"] = True
            root_dev_deps[spec["name"]] = spec["root_range"]
        else:
            root_deps[spec["name"]] = spec["root_range"]
        nodes[f"node_modules/{spec['name']}"] = node

    # Pass 2 — a second requirement on a sibling, attached to a production host
    # node so the constraint is reachable only by walking non-root nodes; some are
    # also mirrored as a genuinely nested install to exercise deep name parsing.
    hosts = [spec["name"] for spec in specs if not spec["dev"]]
    for idx, spec in enumerate(specs):
        if spec["second_range"] is None or not hosts:
            continue
        target = specs[(idx + 1) % len(specs)]["name"]
        host = hosts[idx % len(hosts)]
        if host == target:
            continue
        nodes[f"node_modules/{host}"].setdefault("dependencies", {})[target] = spec["second_range"]
        if rng.random() < 0.5:
            nested_key = f"node_modules/{host}/node_modules/{target}"
            nested_node: dict = {"version": by_name[target]["installed"]}
            if by_name[target]["dev"]:
                nested_node["dev"] = True
            nodes.setdefault(nested_key, nested_node)

    lockfile = {
        "name": "generated-project",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "generated-project", "version": "0.0.0",
                 "dependencies": root_deps, "devDependencies": root_dev_deps},
            **nodes,
        },
    }
    return lockfile, registry, advisories

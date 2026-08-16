"""Independent oracle and fixtures for the ffguard verifier.

Nothing here imports the tool under test. The kit re-implements Debian version
ordering, OSV range containment, the hardening decision policy, canonical JSON
and the exact artifact byte layout in Python, mints host-state inventories and
advisory sets, and serves them over an OSV-compatible mock so the tool's output
can be compared against a from-scratch reference.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

FFMPEG_TOOLS = ("ffmpeg", "ffprobe")
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# --------------------------------------------------------------------------- #
# Debian version comparison (dpkg semantics)
# --------------------------------------------------------------------------- #
def _order(character: str) -> int:
    if character == "" or character.isdigit():
        return 0
    code = ord(character)
    if character.isalpha():
        return code
    if character == "~":
        return -1
    return code + 256


def _verrevcmp(left: str, right: str) -> int:
    i = j = 0
    la, lb = len(left), len(right)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not left[i].isdigit()) or (j < lb and not right[j].isdigit()):
            a = _order(left[i] if i < la else "")
            b = _order(right[j] if j < lb else "")
            if a != b:
                return a - b
            i += 1
            j += 1
        while i < la and left[i] == "0":
            i += 1
        while j < lb and right[j] == "0":
            j += 1
        while i < la and j < lb and left[i].isdigit() and right[j].isdigit():
            if first_diff == 0:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < la and left[i].isdigit():
            return 1
        if j < lb and right[j].isdigit():
            return -1
        if first_diff != 0:
            return first_diff
    return 0


def _parse(version: str) -> tuple[int, str, str]:
    epoch = 0
    rest = version
    if ":" in version:
        head, rest = version.split(":", 1)
        epoch = int(head)
    upstream, revision = rest, ""
    if "-" in rest:
        idx = rest.rfind("-")
        upstream, revision = rest[:idx], rest[idx + 1:]
    return epoch, upstream, revision


def compare_deb(left: str, right: str) -> int:
    """Compare two Debian version strings; return -1, 0 or 1."""
    ea, ua, ra = _parse(left)
    eb, ub, rb = _parse(right)
    if ea != eb:
        return -1 if ea < eb else 1
    upstream = _verrevcmp(ua, ub)
    if upstream != 0:
        return -1 if upstream < 0 else 1
    revision = _verrevcmp(ra, rb)
    return -1 if revision < 0 else (1 if revision > 0 else 0)


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #
def canonical_json(value: Any) -> bytes:
    """Recursively key-sorted, compact, newline-terminated UTF-8 JSON."""
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


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
            intervals.append((introduced if introduced is not None else "0", "fixed", event["fixed"]))
            introduced = None
        elif "last_affected" in event:
            intervals.append(
                (introduced if introduced is not None else "0", "last_affected", event["last_affected"])
            )
            introduced = None
    if introduced is not None:
        intervals.append((introduced, "open", None))
    return intervals


def _range_hit(events: list[dict], version: str) -> tuple[bool, str | None]:
    for intro, kind, end in _intervals(events):
        if not (intro == "0" or compare_deb(version, intro) >= 0):
            continue
        if kind == "open":
            return True, None
        if kind == "fixed" and compare_deb(version, end) < 0:
            return True, end
        if kind == "last_affected" and compare_deb(version, end) <= 0:
            return True, None
    return False, None


def advisory_hit(vuln: dict, package: str, version: str) -> tuple[bool, str | None]:
    """Return (applicable, fixed_version) for a vuln against package@version.

    Withdrawn advisories, non-ECOSYSTEM ranges, and affected blocks for other
    packages or ecosystems never apply.
    """
    if "withdrawn" in vuln:
        return False, None
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package or pkg.get("ecosystem") != "Debian":
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            hit, fixed = _range_hit(rng.get("events", []), version)
            if hit:
                return True, fixed
    return False, None


# --------------------------------------------------------------------------- #
# Decision policy + oracle artifacts
# --------------------------------------------------------------------------- #
def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def resolve_service(conn: sqlite3.Connection, exec_path: str) -> tuple[str | None, str | None]:
    row = conn.execute("SELECT package FROM binaries WHERE path = ?", (exec_path,)).fetchone()
    if row is None or row[0] is None:
        return None, None
    package = row[0]
    prow = conn.execute("SELECT version FROM packages WHERE name = ?", (package,)).fetchone()
    if prow is None:
        return None, None
    return package, prow[0]


def decide(package: str | None, version: str | None, advisories: list[dict]) -> dict:
    if version is None or package is None:
        return {"decision": "block", "reason": "unverifiable", "pin_version": None,
                "max_severity": None, "advisories": []}
    applicable = []
    for vuln in advisories:
        hit, fixed = advisory_hit(vuln, package, version)
        if hit:
            applicable.append((vuln, fixed))
    if not applicable:
        return {"decision": "ok", "reason": "clean", "pin_version": None,
                "max_severity": None, "advisories": []}
    ids = sorted(v["id"] for v, _ in applicable)
    severity = max(
        (v.get("database_specific", {}).get("severity", "LOW") for v, _ in applicable),
        key=SEVERITIES.index,
    )
    if any(fixed is None for _, fixed in applicable):
        return {"decision": "block", "reason": "no_fix", "pin_version": None,
                "max_severity": severity, "advisories": ids}
    target = None
    for _, fixed in applicable:
        if target is None or compare_deb(fixed, target) > 0:
            target = fixed
    if any(advisory_hit(vuln, package, target)[0] for vuln in advisories):
        return {"decision": "block", "reason": "no_safe_version", "pin_version": None,
                "max_severity": severity, "advisories": ids}
    return {"decision": "pin", "reason": "vulnerable_fixable", "pin_version": target,
            "max_severity": severity, "advisories": ids}


def service_rows(db_path: str, advisories_by_pkg: dict[str, list[dict]]) -> list[dict]:
    conn = sqlite3.connect(db_path)
    services = conn.execute("SELECT unit, exec_path, enabled FROM services ORDER BY unit").fetchall()
    rows = []
    for unit, exec_path, enabled in services:
        if _basename(exec_path) not in FFMPEG_TOOLS:
            continue
        package, version = resolve_service(conn, exec_path)
        adv = advisories_by_pkg.get(package, []) if package else []
        decision = decide(package, version, adv)
        rows.append({
            "unit": unit,
            "enabled": bool(enabled),
            "exec_path": exec_path,
            "package": package,
            "installed_version": version,
            "decision": decision["decision"],
            "reason": decision["reason"],
            "pin_version": decision["pin_version"],
            "max_severity": decision["max_severity"],
            "advisories": decision["advisories"],
        })
    conn.close()
    rows.sort(key=lambda r: r["unit"])
    return rows


def pin_targets(rows: list[dict]) -> dict[str, str]:
    targets: dict[str, str] = {}
    for row in rows:
        if row["decision"] == "pin":
            pkg, tgt = row["package"], row["pin_version"]
            if pkg not in targets or compare_deb(tgt, targets[pkg]) > 0:
                targets[pkg] = tgt
    return targets


def render_markdown(rows: list[dict]) -> str:
    pinned = sum(1 for r in rows if r["decision"] == "pin")
    blocked = sum(1 for r in rows if r["decision"] == "block")
    compliant = sum(1 for r in rows if r["decision"] == "ok")
    lines = [
        "# FFmpeg transcode hardening audit",
        "",
        f"Services scanned: {len(rows)}",
        f"Pinned: {pinned}",
        f"Blocked: {blocked}",
        f"Compliant: {compliant}",
        "",
    ]
    for row in rows:
        pkg = row["package"] if row["package"] is not None else "untracked"
        ver = row["installed_version"] if row["installed_version"] is not None else "unknown"
        if row["decision"] == "pin":
            verdict = f"PINNED to {row['pin_version']}"
        elif row["decision"] == "block":
            verdict = f"BLOCKED ({row['reason']})"
        else:
            verdict = "COMPLIANT"
        advisories = ", ".join(row["advisories"]) if row["advisories"] else "none"
        lines += [
            f"## {row['unit']}",
            "",
            f"- Executable: {row['exec_path']}",
            f"- Package: {pkg}",
            f"- Installed version: {ver}",
            f"- Decision: {verdict}",
            f"- Advisories: {advisories}",
            "",
        ]
    return "\n".join(lines)


def build_oracle(db_path: str, advisories_by_pkg: dict[str, list[dict]]) -> dict[str, bytes]:
    """Return {relative_path: expected_bytes} for every artifact the tool writes."""
    rows = service_rows(db_path, advisories_by_pkg)
    targets = pin_targets(rows)
    pins = [{"package": p, "version": targets[p]} for p in sorted(targets)]
    blocked = sorted(r["unit"] for r in rows if r["decision"] == "block")
    report = {
        "generated_by": "ffguard",
        "report_version": "1",
        "services": rows,
        "pins": pins,
        "blocked_units": blocked,
    }
    artifacts: dict[str, bytes] = {"hardening-report.json": canonical_json(report)}
    for pkg in sorted(targets):
        artifacts[f"apt/preferences.d/ffguard-{pkg}.pref"] = (
            f"Package: {pkg}\nPin: version {targets[pkg]}\nPin-Priority: 1001\n".encode()
        )
    for row in rows:
        if row["decision"] == "block":
            artifacts[f"systemd/system/{row['unit']}.d/override.conf"] = (
                "[Service]\nExecStart=\nExecStart=/bin/false\n"
                "NoNewPrivileges=yes\nProtectSystem=strict\n".encode()
            )
    artifacts["ffmpeg-hardening-audit.md"] = render_markdown(rows).encode()
    return artifacts


# --------------------------------------------------------------------------- #
# Artifact parsers
#
# Text artifacts are verified by parsing rather than byte comparison: content,
# values and ordering are checked strictly while incidental whitespace is not.
# --------------------------------------------------------------------------- #
def parse_pref(text: str) -> dict[str, str]:
    """Parse an APT preferences stanza into its field values."""
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"not an APT preferences field: {raw!r}")
        fields[name.strip()] = value.strip()
    return fields


def parse_override(text: str) -> tuple[list[str], dict[str, list[str]]]:
    """Parse a systemd drop-in into its section list and per-key value lists.

    Value lists keep order, which matters for ExecStart= reset semantics.
    """
    sections: list[str] = []
    values: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.append(current)
            continue
        name, separator, value = line.partition("=")
        if not separator or current is None:
            raise ValueError(f"not a systemd unit directive: {raw!r}")
        values.setdefault(f"{current}.{name.strip()}", []).append(value.strip())
    return sections, values


def parse_audit_md(text: str) -> dict:
    """Parse the Markdown audit note into summary counts and ordered unit sections."""
    if not text.endswith("\n"):
        raise ValueError("audit note must end with a newline")
    lines = [line.rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line != ""]
    if not lines or lines[0] != "# FFmpeg transcode hardening audit":
        raise ValueError("missing audit note title")
    summary: dict[str, int] = {}
    index = 1
    for label in ("Services scanned", "Pinned", "Blocked", "Compliant"):
        if index >= len(lines) or not lines[index].startswith(f"{label}:"):
            raise ValueError(f"missing summary line for {label}")
        summary[label] = int(lines[index].partition(":")[2].strip())
        index += 1
    sections: list[dict] = []
    current: dict | None = None
    for line in lines[index:]:
        if line.startswith("## "):
            current = {"unit": line[3:].strip(), "fields": []}
            sections.append(current)
        elif line.startswith("- ") and current is not None:
            name, _, value = line[2:].partition(": ")
            current["fields"].append((name.strip(), value.strip()))
        else:
            raise ValueError(f"unexpected line in audit note: {line!r}")
    return {"summary": summary, "sections": sections}


# --------------------------------------------------------------------------- #
# Inventory writer
# --------------------------------------------------------------------------- #
_SCHEMA = (
    "CREATE TABLE packages (name TEXT PRIMARY KEY, version TEXT NOT NULL, ecosystem TEXT NOT NULL);"
    "CREATE TABLE binaries (path TEXT PRIMARY KEY, package TEXT);"
    "CREATE TABLE services (unit TEXT PRIMARY KEY, exec_path TEXT NOT NULL, enabled INTEGER NOT NULL);"
)


def write_db(path: str, packages: list, binaries: list, services: list) -> None:
    """Materialize a host-state inventory database."""
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    conn.executemany("INSERT INTO packages VALUES (?,?,?)", packages)
    conn.executemany("INSERT INTO binaries VALUES (?,?)", binaries)
    conn.executemany("INSERT INTO services VALUES (?,?,?)", services)
    conn.commit()
    conn.close()


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
                    package = json.loads(raw)["package"]
                    name = package["name"]
                    ecosystem = package.get("ecosystem")
                except (ValueError, KeyError, TypeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                # The contract requires the query to name the Debian ecosystem; a
                # request that omits or mis-states it is rejected, so a tool that
                # skips the ecosystem field cannot obtain advisories.
                if ecosystem != "Debian":
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
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> OsvServer:
        self._thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- #
# Deterministic host generator
# --------------------------------------------------------------------------- #
def _debver(rng) -> str:
    epoch = rng.choice(["", "", "7:", "1:"])
    upstream = f"{rng.choice(['4', '5', '6', '7'])}.{rng.randrange(0, 4)}.{rng.randrange(0, 12)}"
    if rng.random() < 0.2:
        upstream += f"~rc{rng.randrange(1, 3)}"
    revision = rng.choice(["-1", "-0+deb12u1", "-0+deb11u1", "-2", ""])
    return f"{epoch}{upstream}{revision}"


def _events(rng, major: str) -> list[dict]:
    style = rng.random()
    if style < 0.35:
        return [{"introduced": rng.choice(["0", f"{major}.0"])},
                {"fixed": f"{major}.{rng.randrange(1, 9)}.{rng.randrange(1, 9)}-1"}]
    if style < 0.55:
        return [{"introduced": rng.choice(["0", f"{major}.0"])}]
    if style < 0.75:
        return [{"introduced": f"{major}.0"},
                {"last_affected": f"{major}.{rng.randrange(1, 9)}.{rng.randrange(1, 9)}-1"}]
    return [{"introduced": "0"}, {"fixed": f"{major}.0"},
            {"introduced": f"{major}.5"}, {"fixed": f"{major}.9.0-1"}]


def generate_host(rng) -> tuple[list, list, list, dict]:
    """Mint one randomized but self-consistent host inventory and advisory set."""
    packages, advisories = [], {}
    for i in range(rng.randrange(2, 7)):
        name = f"ffpkg{i}"
        version = _debver(rng)
        packages.append((name, version, "Debian"))
        major = version.split(":")[-1].split(".")[0]
        vulns = []
        for j in range(rng.randrange(0, 4)):
            affected = [{"package": {"name": name, "ecosystem": "Debian"},
                         "ranges": [{"type": "ECOSYSTEM", "events": _events(rng, major)}]}]
            # A real Debian ECOSYSTEM block may sit beside decoy ranges and
            # blocks (other range types, packages or ecosystems) that must be ignored.
            if rng.random() < 0.3:
                affected[0]["ranges"].insert(0, {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]})
            if rng.random() < 0.3:
                affected.append({"package": {"name": name, "ecosystem": "npm"},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]})
            if rng.random() < 0.3:
                affected.append({"package": {"name": f"other-{i}", "ecosystem": "Debian"},
                                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]})
            vuln = {
                "id": f"OSV-{i:02d}{j:02d}",
                "affected": affected,
                "database_specific": {"severity": rng.choice(SEVERITIES)},
            }
            if rng.random() < 0.2:
                vuln["withdrawn"] = "2026-01-01T00:00:00Z"
            vulns.append(vuln)
        advisories[name] = vulns
    packages.append(("nginx", "1.22.1-9", "Debian"))

    binaries, services = [], []
    for s in range(rng.randrange(3, 10)):
        tool = rng.choice(FFMPEG_TOOLS)
        path = f"/srv/s{s}/{tool}"
        style = rng.random()
        if style < 0.15:
            pass  # no binaries row -> unverifiable
        elif style < 0.3:
            binaries.append((path, None))  # untracked
        elif style < 0.45:
            binaries.append((path, f"ghost{s}"))  # package missing from packages
        else:
            binaries.append((path, rng.choice([p[0] for p in packages])))
        services.append((f"svc{s}.service", path, rng.randrange(2)))
    binaries.append(("/usr/sbin/nginx", "nginx"))
    services.append(("web.service", "/usr/sbin/nginx", 1))
    binaries.append(("/usr/bin/transcoder", rng.choice([p[0] for p in packages])))
    services.append(("transcoder.service", "/usr/bin/transcoder", 1))  # basename out of scope

    seen: dict[str, Any] = {}
    for path, pkg in binaries:
        seen.setdefault(path, pkg)
    binaries = [(path, seen[path]) for path in seen]
    return packages, binaries, services, advisories

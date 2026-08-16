"""Independent oracle and fixtures for the certguard verifier.

Nothing here imports the tool under test. The kit re-implements certificate
fingerprints, chain building and validation, CRL revocation, the rotation
decision policy, canonical JSON and the exact artifact byte layout in Python,
mints TLS inventories, and serves the CRLs over a mock revocation service, so the
tool's output can be compared against a from-scratch reference.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# --------------------------------------------------------------------------- #
# Canonical JSON and fingerprints
# --------------------------------------------------------------------------- #
def canonical_compact(value: Any) -> bytes:
    """Recursively key-sorted, compact JSON with no trailing newline."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def canonical_json(value: Any) -> bytes:
    """Canonical JSON with exactly one trailing newline."""
    return canonical_compact(value) + b"\n"


def normalize_serial(serial: str) -> str:
    return format(serial_value(serial), "x")


def serial_value(serial: str) -> int:
    serial = serial.strip()
    if serial.lower().startswith("0x"):
        return int(serial[2:], 16)
    return int(serial, 10)


def fingerprint_object(cert: dict) -> dict:
    nc = cert.get("name_constraints")
    if nc is not None:
        nc = {"excluded": list(nc.get("excluded") or []), "permitted": list(nc.get("permitted") or [])}
    return {
        "aki": cert["authority_key_id"],
        "eku": list(cert.get("ext_key_usages") or []),
        "is_ca": bool(cert["is_ca"]),
        "ku": list(cert.get("key_usages") or []),
        "name_constraints": nc,
        "not_after": cert["not_after"],
        "not_before": cert["not_before"],
        "path_len": cert.get("path_len"),
        "sans": list(cert.get("sans") or []),
        "serial": normalize_serial(cert["serial"]),
        "ski": cert["subject_key_id"],
        "subject": cert["subject"],
    }


def fp_hex(cert: dict) -> str:
    return hashlib.sha256(canonical_compact(fingerprint_object(cert))).hexdigest()


def fingerprint(cert: dict) -> str:
    return "sha256:" + fp_hex(cert)


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #
def parse_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


# --------------------------------------------------------------------------- #
# Inventory access
# --------------------------------------------------------------------------- #
class Inventory:
    def __init__(self, data: dict):
        self.certificates: list[dict] = data["certificates"]
        self.services: list[dict] = data["services"]
        self.trust_store: set[str] = set(data["trust_store"])
        self.policy: dict = data["policy"]
        self.by_id = {c["id"]: c for c in self.certificates}
        self.by_ski = {c["subject_key_id"]: c for c in self.certificates}

    def is_anchor(self, ski: str) -> bool:
        return ski in self.trust_store


# --------------------------------------------------------------------------- #
# Chain building and structural validation
# --------------------------------------------------------------------------- #
def build_chain(inv: Inventory, leaf: dict) -> tuple[list[dict], bool]:
    chain = [leaf]
    seen = {leaf["subject_key_id"]}
    current = leaf
    while True:
        if inv.is_anchor(current["subject_key_id"]):
            return chain, True
        if current["authority_key_id"] == current["subject_key_id"]:
            return chain, False
        issuer = inv.by_ski.get(current["authority_key_id"])
        if issuer is None or issuer["subject_key_id"] in seen:
            return chain, False
        seen.add(issuer["subject_key_id"])
        chain.append(issuer)
        current = issuer


def san_match(san: str, name: str) -> bool:
    san = san.lower()
    name = name.lower()
    if san.startswith("*."):
        suffix = san[2:]
        dot = name.find(".")
        if dot < 0:
            return False
        return name[dot + 1:] == suffix
    return san == name


def subtree_match(name: str, subtree: str) -> bool:
    name = name.lower()
    subtree = subtree.lower()
    return name == subtree or name.endswith("." + subtree)


def server_identity_ok(leaf: dict, server_name: str) -> bool:
    return any(san_match(s, server_name) for s in (leaf.get("sans") or []))


def validate_structure(inv: Inventory, chain: list[dict], server_name: str, t: datetime) -> bool:
    n = len(chain) - 1
    if n < 0 or not inv.is_anchor(chain[n]["subject_key_id"]):
        return False
    for i, cert in enumerate(chain):
        if i > 0 and (not cert["is_ca"] or "certSign" not in (cert.get("key_usages") or [])):
            return False
        if i < n:
            if t < parse_time(cert["not_before"]) or t > parse_time(cert["not_after"]):
                return False
        if i >= 1 and cert.get("path_len") is not None and (i - 1) > cert["path_len"]:
            return False
        eku = cert.get("ext_key_usages") or []
        if eku and "serverAuth" not in eku and "anyExtendedKeyUsage" not in eku:
            return False
        if i >= 1 and cert.get("name_constraints") is not None:
            nc = cert["name_constraints"]
            permitted = nc.get("permitted") or []
            if permitted and not any(subtree_match(server_name, s) for s in permitted):
                return False
            if any(subtree_match(server_name, s) for s in (nc.get("excluded") or [])):
                return False
    return server_identity_ok(chain[0], server_name)


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #
def cert_revoked(cert: dict, t: datetime, crls: dict) -> bool:
    crl = crls.get(cert["authority_key_id"])
    if crl is None:
        return False
    if t < parse_time(crl["this_update"]) or t > parse_time(crl["next_update"]):
        return True
    want = serial_value(cert["serial"])
    for entry in crl.get("entries", []):
        if entry.get("reason") == "removeFromCRL":
            continue
        if serial_value(entry["serial"]) == want:
            return True
    return False


def chain_revoked(chain: list[dict], t: datetime, crls: dict) -> bool:
    return any(cert_revoked(cert, t, crls) for cert in chain[:-1])


# --------------------------------------------------------------------------- #
# Decision policy
# --------------------------------------------------------------------------- #
def evaluate(inv: Inventory, crls: dict) -> list[dict]:
    t = parse_time(inv.policy["evaluated_at"])
    window = timedelta(days=inv.policy["rotation_window_days"])
    rows = []
    for svc in inv.services:
        server_name = svc["server_name"]
        evals: dict[str, dict] = {}

        def eval_leaf(leaf: dict) -> dict:
            if leaf["id"] in evals:
                return evals[leaf["id"]]
            chain, anchored = build_chain(inv, leaf)
            info = {"chain": chain, "anchored": anchored, "struct_ok": False, "revoked": False}
            if anchored:
                info["struct_ok"] = validate_structure(inv, chain, server_name, t)
                info["revoked"] = chain_revoked(chain, t, crls)
            evals[leaf["id"]] = info
            return info

        bound = inv.by_id.get(svc["bound_id"])
        if bound is not None and not bound["is_ca"]:
            eval_leaf(bound)

        candidates = []
        for cert in inv.certificates:
            if cert["is_ca"] or not server_identity_ok(cert, server_name):
                continue
            info = eval_leaf(cert)
            usable = info["anchored"] and info["struct_ok"] and not info["revoked"]
            fresh = (parse_time(cert["not_after"]) - t) >= window
            if usable and fresh:
                candidates.append(cert)

        row = {
            "unit": svc["unit"],
            "server_name": server_name,
            "enabled": bool(svc["enabled"]),
            "bound_id": svc["bound_id"],
            "anchored": False,
            "bound_fingerprint": None,
            "bound_not_after": None,
            "chain": [],
            "replacement_fingerprint": None,
        }
        status = _classify(inv, bound, evals, t, window, server_name, row)

        best = _best_replacement(candidates, t)
        if status == "compliant":
            row["decision"], row["reason"] = "ok", "compliant"
        elif best is not None:
            row["decision"], row["reason"] = "rotate", status
            row["replacement_fingerprint"] = fingerprint(best)
        else:
            row["decision"], row["reason"] = "block", status
        rows.append(row)

    rows.sort(key=lambda r: r["unit"])
    return rows


def _classify(inv, bound, evals, t, window, server_name, row) -> str:
    if bound is None or bound["is_ca"]:
        row["chain"] = []
        return "missing"
    row["bound_fingerprint"] = fingerprint(bound)
    row["bound_not_after"] = bound["not_after"]
    info = evals[bound["id"]]
    row["anchored"] = info["anchored"]
    row["chain"] = [fingerprint(c) for c in info["chain"]] if info["anchored"] else []
    if t < parse_time(bound["not_before"]) or t > parse_time(bound["not_after"]):
        return "expired"
    if not (info["anchored"] and info["struct_ok"]):
        return "untrusted"
    if info["revoked"]:
        return "revoked"
    if (parse_time(bound["not_after"]) - t) < window:
        return "expiring"
    return "compliant"


def _best_replacement(candidates: list[dict], t: datetime):
    if not candidates:
        return None
    return max(candidates, key=lambda c: (parse_time(c["not_after"]), serial_value(c["serial"]), fp_hex(c)))


# --------------------------------------------------------------------------- #
# Expected revocation query set
# --------------------------------------------------------------------------- #
def expected_queries(inv: Inventory) -> set[str]:
    queried: set[str] = set()
    for svc in inv.services:
        server_name = svc["server_name"]
        relevant = []
        bound = inv.by_id.get(svc["bound_id"])
        if bound is not None and not bound["is_ca"]:
            relevant.append(bound)
        relevant.extend(c for c in inv.certificates if not c["is_ca"] and server_identity_ok(c, server_name))
        seen = set()
        for leaf in relevant:
            if leaf["id"] in seen:
                continue
            seen.add(leaf["id"])
            chain, anchored = build_chain(inv, leaf)
            if anchored:
                for cert in chain[:-1]:
                    queried.add(cert["authority_key_id"])
    return queried


# --------------------------------------------------------------------------- #
# Oracle artifacts
# --------------------------------------------------------------------------- #
SYSTEMD_OVERRIDE = (
    "[Service]\nExecStart=\nExecStart=/bin/false\nNoNewPrivileges=yes\nProtectSystem=strict\n"
)


def build_oracle(inv: Inventory, crls: dict) -> dict[str, bytes]:
    rows = evaluate(inv, crls)
    services = []
    rotations = []
    blocked = []
    artifacts: dict[str, bytes] = {}

    for r in rows:
        services.append({
            "unit": r["unit"],
            "server_name": r["server_name"],
            "enabled": r["enabled"],
            "bound_id": r["bound_id"],
            "decision": r["decision"],
            "reason": r["reason"],
            "anchored": r["anchored"],
            "bound_fingerprint": r["bound_fingerprint"],
            "bound_not_after": r["bound_not_after"],
            "chain": r["chain"],
            "replacement_fingerprint": r["replacement_fingerprint"],
        })
        if r["decision"] == "rotate":
            hex_part = r["replacement_fingerprint"][len("sha256:"):]
            artifacts[f"nginx/snippets/{r['unit']}.conf"] = (
                f"# certguard: rotated {r['unit']} ({r['reason']})\n"
                f"ssl_certificate     /etc/certguard/certs/{hex_part}.pem;\n"
                f"ssl_certificate_key /etc/certguard/private/{hex_part}.key;\n"
            ).encode("utf-8")
            rotations.append({"unit": r["unit"], "fingerprint": r["replacement_fingerprint"]})
        elif r["decision"] == "block":
            artifacts[f"systemd/system/{r['unit']}.d/override.conf"] = SYSTEMD_OVERRIDE.encode("utf-8")
            blocked.append(r["unit"])

    report = {
        "generated_by": "certguard",
        "report_version": "1",
        "evaluated_at": inv.policy["evaluated_at"],
        "services": services,
        "rotations": rotations,
        "blocked_units": blocked,
    }
    artifacts["tls-trust-report.json"] = canonical_json(report)
    artifacts["tls-rotation-audit.md"] = render_markdown(inv.policy["evaluated_at"], rows).encode("utf-8")
    return artifacts


def render_markdown(evaluated_at: str, rows: list[dict]) -> str:
    rotated = sum(1 for r in rows if r["decision"] == "rotate")
    blocked = sum(1 for r in rows if r["decision"] == "block")
    compliant = sum(1 for r in rows if r["decision"] == "ok")
    lines = [
        "# TLS service rotation audit",
        "",
        f"Evaluated at: {evaluated_at}",
        f"Services scanned: {len(rows)}",
        f"Rotated: {rotated}",
        f"Blocked: {blocked}",
        f"Compliant: {compliant}",
        "",
    ]
    for r in rows:
        if r["chain"]:
            chain_str = " > ".join(fp[len("sha256:"):] for fp in r["chain"])
        else:
            chain_str = "none"
        if r["decision"] == "rotate":
            verdict = f"ROTATED to {r['replacement_fingerprint'][len('sha256:'):]}"
        elif r["decision"] == "block":
            verdict = f"BLOCKED ({r['reason']})"
        else:
            verdict = "COMPLIANT"
        lines += [
            f"## {r['unit']}",
            "",
            f"- Server name: {r['server_name']}",
            f"- Bound certificate: {r['bound_id']}",
            f"- Chain: {chain_str}",
            f"- Decision: {verdict}",
            "",
        ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Inventory writer
# --------------------------------------------------------------------------- #
def write_inventory(dir_path: str, inv_data: dict) -> None:
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, "certificates.json"), "w", encoding="utf-8") as fh:
        json.dump(inv_data["certificates"], fh)
    with open(os.path.join(dir_path, "services.json"), "w", encoding="utf-8") as fh:
        json.dump(inv_data["services"], fh)
    with open(os.path.join(dir_path, "trust-store.json"), "w", encoding="utf-8") as fh:
        json.dump(inv_data["trust_store"], fh)
    with open(os.path.join(dir_path, "policy.json"), "w", encoding="utf-8") as fh:
        json.dump(inv_data["policy"], fh)


# --------------------------------------------------------------------------- #
# Mock revocation service
# --------------------------------------------------------------------------- #
class RevocationServer:
    """Threaded mock that serves CRLs and records the issuers it was queried for."""

    def __init__(self, crls: dict, port: int = 0):
        self.queried: list[str] = []
        crl_map = crls
        queried = self.queried

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):  # noqa: N802
                if self.path != "/v1/revocations":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    issuer = json.loads(raw)["issuer_key_id"]
                except (ValueError, KeyError, TypeError):
                    self.send_response(400)
                    self.end_headers()
                    return
                queried.append(issuer)
                payload = json.dumps({"crl": crl_map.get(issuer)}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "RevocationServer":
        self._thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- #
# Artifact parsers (semantic, whitespace-tolerant except canonical JSON)
# --------------------------------------------------------------------------- #
def parse_nginx(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(";"):
            line = line[:-1]
        key, _, value = line.partition(" ")
        fields[key.strip()] = value.strip()
    return fields


def parse_override(text: str) -> tuple[list[str], dict[str, list[str]]]:
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
        name, sep, value = line.partition("=")
        if not sep or current is None:
            raise ValueError(f"not a systemd directive: {raw!r}")
        values.setdefault(f"{current}.{name.strip()}", []).append(value.strip())
    return sections, values


# --------------------------------------------------------------------------- #
# Deterministic inventory generator
# --------------------------------------------------------------------------- #
_SCENARIOS = [
    "compliant", "expiring", "expired", "revoked", "revoked_stale", "revoked_removed",
    "untrusted_root", "untrusted_san", "untrusted_intexpired", "untrusted_nc",
    "untrusted_pathlen", "untrusted_eku", "missing",
]


def _alt_serial(rng, serial: str) -> str:
    """Return an equivalent serial in a different textual form to exercise
    value-based comparison."""
    value = serial_value(serial)
    choice = rng.randrange(3)
    if choice == 0:
        return str(value)
    if choice == 1:
        return hex(value)
    return "0x" + format(value, "x").rjust(8, "0")  # leading zeros


def generate_inventory(rng) -> tuple[dict, dict]:
    """Mint one randomized but self-consistent TLS inventory and CRL set."""
    base = datetime(2026, 7, 1, tzinfo=timezone.utc)

    def ts(days: float) -> str:
        return (base + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    window = rng.choice([14, 30, 45])
    certs: list[dict] = []
    services: list[dict] = []
    crls: dict = {}
    counters = {"ski": 0, "serial": 1000}

    def ski(prefix: str = "k") -> str:
        counters["ski"] += 1
        return f"{prefix}{counters['ski']:03d}"

    def serial() -> str:
        counters["serial"] += 1
        value = counters["serial"] * 13 + rng.randrange(1, 97)
        return hex(value) if rng.random() < 0.5 else str(value)

    def add_ca(subject, s_ski, aki, nb, na, path_len=None, nc=None, eku=None) -> dict:
        cert = {
            "id": f"ca-{s_ski}", "subject": subject, "subject_key_id": s_ski,
            "authority_key_id": aki, "serial": serial(), "not_before": nb, "not_after": na,
            "is_ca": True, "path_len": path_len, "key_usages": ["certSign", "crlSign"],
            "ext_key_usages": eku or [], "sans": [], "name_constraints": nc,
        }
        certs.append(cert)
        return cert

    def add_leaf(cid, subject, s_ski, aki, nb, na, sans) -> dict:
        cert = {
            "id": cid, "subject": subject, "subject_key_id": s_ski, "authority_key_id": aki,
            "serial": serial(), "not_before": nb, "not_after": na, "is_ca": False,
            "path_len": None, "key_usages": ["digitalSignature"], "ext_key_usages": ["serverAuth"],
            "sans": sans, "name_constraints": None,
        }
        certs.append(cert)
        return cert

    root1 = add_ca("Root T1", ski("root"), None, ts(-3000), ts(3000))
    root1["authority_key_id"] = root1["subject_key_id"]
    root2 = add_ca("Root T2", ski("root"), None, ts(-3000), ts(3000))
    root2["authority_key_id"] = root2["subject_key_id"]
    root_u = add_ca("Root U", ski("uroot"), None, ts(-3000), ts(3000))
    root_u["authority_key_id"] = root_u["subject_key_id"]
    trust = [root1["subject_key_id"], root2["subject_key_id"]]

    for i in range(rng.randrange(4, 9)):
        name = f"svc{i}.example.com"
        root = rng.choice([root1, root2])
        nc = {"permitted": ["example.com"], "excluded": []} if rng.random() < 0.25 else None
        inter = add_ca(f"Int {i}", ski("int"), root["subject_key_id"], ts(-800), ts(1500),
                       path_len=rng.choice([None, None, 1, 2]), nc=nc)
        scenario = rng.choice(_SCENARIOS)

        bound_issuer = inter["subject_key_id"]
        nb, na = ts(-100), ts(500)
        sans = [name]
        bound_id = f"leaf-{i}"
        make_bound = True

        if scenario == "expiring":
            na = ts(window - 3)
        elif scenario == "expired":
            nb, na = ts(-400), ts(-10)
        elif scenario == "untrusted_san":
            sans = [f"other{i}.example.com"]
        elif scenario == "untrusted_root":
            uinter = add_ca(f"UInt {i}", ski("int"), root_u["subject_key_id"], ts(-800), ts(1500))
            bound_issuer = uinter["subject_key_id"]
        elif scenario == "untrusted_intexpired":
            inter["not_after"] = ts(-50)
        elif scenario == "untrusted_nc":
            inter["name_constraints"] = {"permitted": [], "excluded": [name]}
        elif scenario == "untrusted_pathlen":
            inter["path_len"] = 0
            sub = add_ca(f"SubInt {i}", ski("int"), inter["subject_key_id"], ts(-700), ts(1400))
            bound_issuer = sub["subject_key_id"]
        elif scenario == "untrusted_eku":
            inter["ext_key_usages"] = ["clientAuth"]
        elif scenario == "missing":
            make_bound = False
            bound_id = f"ghost-{i}"

        if make_bound:
            bound = add_leaf(bound_id, name, ski("leaf"), bound_issuer, nb, na, sans)
            if scenario == "revoked":
                crls[bound_issuer] = {
                    "issuer_key_id": bound_issuer, "this_update": ts(-5), "next_update": ts(20),
                    "entries": [{"serial": _alt_serial(rng, bound["serial"]), "reason": "keyCompromise"}],
                }
            elif scenario == "revoked_stale":
                crls[bound_issuer] = {
                    "issuer_key_id": bound_issuer, "this_update": ts(-60), "next_update": ts(-30),
                    "entries": [],
                }
            elif scenario == "revoked_removed":
                crls[bound_issuer] = {
                    "issuer_key_id": bound_issuer, "this_update": ts(-5), "next_update": ts(20),
                    "entries": [{"serial": _alt_serial(rng, bound["serial"]), "reason": "removeFromCRL"}],
                }

        if scenario != "compliant" and rng.random() < 0.6:
            good = add_ca(f"Good Int {i}", ski("int"), root["subject_key_id"], ts(-800), ts(1500))
            for _ in range(rng.randrange(1, 3)):
                add_leaf(f"repl-{i}-{ski('x')}", name, ski("leaf"), good["subject_key_id"],
                         ts(-50), ts(rng.choice([300, 500, 800])), [name])

        if rng.random() < 0.4:
            add_leaf(f"decoy-{i}", f"decoy{i}.example.org", ski("leaf"), inter["subject_key_id"],
                     ts(-50), ts(700), [f"decoy{i}.example.org"])

        services.append({
            "unit": f"svc{i}.service", "server_name": name, "bound_id": bound_id,
            "enabled": bool(rng.randrange(2)),
        })

    inv_data = {
        "certificates": certs,
        "services": services,
        "trust_store": trust,
        "policy": {"evaluated_at": ts(0), "rotation_window_days": window},
    }
    return inv_data, crls


def parse_audit_md(text: str) -> dict:
    if not text.endswith("\n"):
        raise ValueError("audit note must end with a newline")
    lines = [line.rstrip() for line in text.splitlines()]
    lines = [line for line in lines if line != ""]
    if not lines or lines[0] != "# TLS service rotation audit":
        raise ValueError("missing audit note title")
    summary: dict[str, str] = {}
    index = 1
    for label in ("Evaluated at", "Services scanned", "Rotated", "Blocked", "Compliant"):
        if index >= len(lines) or not lines[index].startswith(f"{label}:"):
            raise ValueError(f"missing summary line for {label}")
        summary[label] = lines[index][len(label) + 1:].strip()
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

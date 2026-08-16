"""Independent oracle and fixtures for the mailguard verifier.

Nothing here imports the tool under test. The kit re-implements the RFC 7208
check-host() decision procedure (left-to-right short-circuit evaluation, the
include-returns-Pass rule, a/mx/exists matching with macro expansion, and the
10-lookup / 2-void limits counted along the evaluated path), static SPF record
analysis, IPv4 CIDR algebra, the spoof-intel feed subtraction, DMARC
parsing/weaknesses/hardening, canonical JSON and the exact artifact byte layout;
mints randomized estates; and serves the DNS resolver and the feed over mock HTTP
servers, so the tool's output can be compared against a from-scratch reference.
"""

from __future__ import annotations

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #
def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- #
# IPv4 CIDR algebra
# --------------------------------------------------------------------------- #
_OCTET_RE = re.compile(r"^\d{1,3}$")
_PREFIX_RE = re.compile(r"^\d{1,2}$")


def _mask_for(prefix: int) -> int:
    if prefix <= 0:
        return 0
    if prefix >= 32:
        return 0xFFFFFFFF
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF


def ip_to_int(ip: str):
    octets = ip.split(".")
    if len(octets) != 4:
        return None
    value = 0
    for octet in octets:
        if not _OCTET_RE.match(octet):
            return None
        n = int(octet)
        if n > 255:
            return None
        value = value * 256 + n
    return value & 0xFFFFFFFF


def _int_to_ip(value: int) -> str:
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def parse_cidr(token: str):
    slash = token.find("/")
    ip_part = token if slash == -1 else token[:slash]
    prefix_part = "32" if slash == -1 else token[slash + 1:]
    if not _PREFIX_RE.match(prefix_part):
        return None
    prefix = int(prefix_part)
    if prefix > 32:
        return None
    value = ip_to_int(ip_part)
    if value is None:
        return None
    return (value & _mask_for(prefix), prefix)


def cidr_string(cidr) -> str:
    return f"{_int_to_ip(cidr[0])}/{cidr[1]}"


def _range_end(cidr) -> int:
    return cidr[0] + 2 ** (32 - cidr[1]) - 1


def contains(outer, inner) -> bool:
    return outer[0] <= inner[0] and _range_end(inner) <= _range_end(outer)


def overlaps(a, b) -> bool:
    return a[0] <= _range_end(b) and b[0] <= _range_end(a)


def cidr_contains_ip(cidr, ip: str) -> bool:
    value = ip_to_int(ip)
    if value is None:
        return False
    return cidr[0] <= value <= _range_end(cidr)


def collapse(cidrs: list) -> list:
    uniq: list = []
    seen: set = set()
    for cidr in cidrs:
        if cidr in seen:
            continue
        seen.add(cidr)
        uniq.append(cidr)
    kept = [c for c in uniq if not any(o[1] < c[1] and contains(o, c) for o in uniq)]
    return sorted(kept, key=lambda c: (c[0], c[1]))


# --------------------------------------------------------------------------- #
# Macro expansion (RFC 7208 section 7)
# --------------------------------------------------------------------------- #
def _macro_value(letter: str, ctx: dict) -> str:
    lower = letter.lower()
    at = ctx["sender"].split("@")
    local = at[0] if len(at) > 1 else "postmaster"
    sender_domain = at[1] if len(at) > 1 else ctx["domain"]
    return {
        "s": ctx["sender"], "l": local, "o": sender_domain, "d": ctx["domain"],
        "i": ctx["ip"], "h": ctx["domain"], "v": "in-addr", "p": "unknown",
    }.get(lower, "")


def _apply_transformer(value: str, digits, reverse: bool, delimiters: str) -> str:
    delims = delimiters if delimiters else "."
    parts = re.split("[" + re.escape(delims) + "]", value)
    if reverse:
        parts = parts[::-1]
    if digits is not None and digits < len(parts):
        parts = parts[len(parts) - digits:]
    return ".".join(parts)


def expand_macros(spec: str, ctx: dict) -> str:
    out = []
    i = 0
    while i < len(spec):
        ch = spec[i]
        if ch != "%":
            out.append(ch)
            i += 1
            continue
        nxt = spec[i + 1] if i + 1 < len(spec) else ""
        if nxt == "%":
            out.append("%")
            i += 2
        elif nxt == "_":
            out.append(" ")
            i += 2
        elif nxt == "-":
            out.append("%20")
            i += 2
        elif nxt == "{":
            close = spec.find("}", i + 2)
            if close == -1:
                out.append(ch)
                i += 1
                continue
            body = spec[i + 2:close]
            letter = body[0]
            rest = body[1:]
            digits = None
            m = re.match(r"^\d+", rest)
            if m:
                digits = int(m.group(0))
                rest = rest[len(m.group(0)):]
            reverse = False
            if rest[:1] in ("r", "R"):
                reverse = True
                rest = rest[1:]
            out.append(_apply_transformer(_macro_value(letter, ctx), digits, reverse, rest))
            i = close + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# DNS access + SPF term parsing
# --------------------------------------------------------------------------- #
def _query(zones: dict, name: str, rtype: str):
    zone = zones.get(name)
    if zone is None:
        return ("NXDOMAIN", [])
    records = zone.get(rtype, [])
    return ("NOERROR", records if isinstance(records, list) else [])


def _is_spf(text: str) -> bool:
    low = text.lstrip().lower()
    return low == "v=spf1" or low.startswith("v=spf1 ")


def _first_spf(zones: dict, domain: str):
    _, records = _query(zones, domain, "TXT")
    matches = [r for r in records if _is_spf(r)]
    return matches[0] if matches else None


_QUAL = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def _parse_term(token: str) -> dict:
    eq = token.find("=")
    if eq != -1:
        key = token[:eq].lower()
        if key in ("redirect", "exp"):
            return {"modifier": True, "qualifier": "+", "name": key, "value": token[eq + 1:], "cidr_len": None}
    qualifier = "+"
    rest = token
    if rest and rest[0] in "+-~?":
        qualifier = rest[0]
        rest = rest[1:]
    colon = rest.find(":")
    if colon != -1:
        name = rest[:colon].lower()
        value = rest[colon + 1:]
    else:
        slash = rest.find("/")
        if slash != -1:
            name = rest[:slash].lower()
            value = rest[slash:]
        else:
            name = rest.lower()
            value = ""
    cidr_len = None
    if name in ("a", "mx"):
        slash = value.find("/")
        if slash != -1:
            tail = value[slash + 1:]
            cidr_len = int(tail) if tail.isdigit() else None
            value = value[:slash]
    return {"modifier": False, "qualifier": qualifier, "name": name, "value": value, "cidr_len": cidr_len}


def _parse_terms(record: str) -> list:
    parts = [p for p in record.strip().split() if p]
    return [_parse_term(p) for p in parts if p.lower() != "v=spf1"]


# --------------------------------------------------------------------------- #
# Static record analysis
# --------------------------------------------------------------------------- #
def _effective_all(zones: dict, domain: str, visited: set) -> str:
    record = _first_spf(zones, domain)
    if record is None:
        return "none"
    redirect = None
    for term in _parse_terms(record):
        if term["modifier"]:
            if term["name"] == "redirect":
                redirect = term["value"]
            continue
        if term["name"] == "all":
            return _QUAL.get(term["qualifier"], "neutral")
    if redirect is not None and redirect not in visited:
        return _effective_all(zones, redirect, visited | {redirect})
    return "none"


def analyze_record(zones: dict, domain: str) -> dict:
    _, records = _query(zones, domain, "TXT")
    spf = [r for r in records if _is_spf(r)]
    if not spf:
        return {"present": False, "multiple": False, "effective_all": "none", "has_ptr": False}
    has_ptr = any((not t["modifier"] and t["name"] == "ptr") for t in _parse_terms(spf[0]))
    return {
        "present": True,
        "multiple": len(spf) > 1,
        "effective_all": _effective_all(zones, domain, {domain}),
        "has_ptr": has_ptr,
    }


# --------------------------------------------------------------------------- #
# check-host(): per-IP evaluation
# --------------------------------------------------------------------------- #
def _charge_lookup(ctx: dict) -> bool:
    ctx["lookups"] += 1
    return ctx["lookups"] > 10


def _charge_void(ctx: dict) -> bool:
    ctx["voids"] += 1
    return ctx["voids"] > 2


def _matches_a(zones: dict, domain: str, cidr_len, ip: str):
    _, records = _query(zones, domain, "A")
    for addr in records:
        cidr = parse_cidr(addr if cidr_len is None else f"{addr}/{cidr_len}")
        if cidr is not None and cidr_contains_ip(cidr, ip):
            return True, False
    return False, len(records) == 0


def _matches_mx(zones: dict, domain: str, cidr_len, ip: str):
    _, records = _query(zones, domain, "MX")
    if len(records) == 0:
        return False, True
    for host in records:
        match, _empty = _matches_a(zones, host, cidr_len, ip)
        if match:
            return True, False
    return False, False


def _check(zones: dict, domain: str, ctx: dict, visited: set) -> str:
    record = _first_spf(zones, domain)
    if record is None:
        return "none"
    redirect = None
    for term in _parse_terms(record):
        if term["modifier"]:
            if term["name"] == "redirect":
                redirect = term["value"]
            continue
        result = _QUAL.get(term["qualifier"], "pass")
        name = term["name"]
        if name == "all":
            return result
        if name == "ip4":
            cidr = parse_cidr(term["value"])
            if cidr is not None and cidr_contains_ip(cidr, ctx["ip"]):
                return result
        elif name == "ip6":
            pass
        elif name == "a":
            if _charge_lookup(ctx):
                return "permerror"
            match, empty = _matches_a(zones, term["value"] or domain, term["cidr_len"], ctx["ip"])
            if empty and _charge_void(ctx):
                return "permerror"
            if match:
                return result
        elif name == "mx":
            if _charge_lookup(ctx):
                return "permerror"
            match, empty = _matches_mx(zones, term["value"] or domain, term["cidr_len"], ctx["ip"])
            if empty and _charge_void(ctx):
                return "permerror"
            if match:
                return result
        elif name == "include":
            if _charge_lookup(ctx):
                return "permerror"
            target = term["value"]
            if target in visited:
                return "permerror"
            sub = _check(zones, target, ctx, visited | {target})
            if sub == "permerror":
                return "permerror"
            if sub == "none":
                return "permerror"
            if sub == "pass":
                return result
            # fail / softfail / neutral -> no match, continue
        elif name == "exists":
            if _charge_lookup(ctx):
                return "permerror"
            mctx = {"ip": ctx["ip"], "domain": domain, "sender": ctx["sender"]}
            qname = expand_macros(term["value"], mctx)
            _, records = _query(zones, qname, "A")
            if len(records) == 0:
                if _charge_void(ctx):
                    return "permerror"
            else:
                return result
        elif name == "ptr":
            if _charge_lookup(ctx):
                return "permerror"
    if redirect is not None:
        if _charge_lookup(ctx):
            return "permerror"
        if redirect in visited:
            return "permerror"
        sub = _check(zones, redirect, ctx, visited | {redirect})
        return "permerror" if sub == "none" else sub
    return "none"


def evaluate_spf(zones: dict, domain: str, ip: str) -> dict:
    ctx = {"ip": ip, "sender": f"probe@{domain}", "lookups": 0, "voids": 0}
    result = _check(zones, domain, ctx, {domain})
    return {"result": result, "lookups": ctx["lookups"]}


def spf_weaknesses(analysis: dict, permerror_observed: bool, flagged_removed: bool) -> list:
    if not analysis["present"]:
        return ["spf_missing"]
    codes = set()
    if analysis["multiple"]:
        codes.add("spf_multiple_records")
    ea = analysis["effective_all"]
    if ea == "pass":
        codes.add("spf_permissive_all")
    if ea == "neutral":
        codes.add("spf_neutral_all")
    if ea == "softfail":
        codes.add("spf_softfail")
    if ea == "none":
        codes.add("spf_no_all")
    if analysis["has_ptr"]:
        codes.add("spf_deprecated_ptr")
    if permerror_observed:
        codes.add("spf_permerror_observed")
    if flagged_removed:
        codes.add("spf_flagged_source")
    return sorted(codes)


# --------------------------------------------------------------------------- #
# SPF hardening
# --------------------------------------------------------------------------- #
def harden_spf(passing_ips: list, flagged: list, config: dict) -> dict:
    raw = [c for c in (parse_cidr(ip) for ip in passing_ips) if c is not None]
    authorized = collapse(raw)
    flagged_cidrs = [c for c in (parse_cidr(s["cidr"]) for s in flagged) if c is not None]
    removed = [c for c in authorized if any(overlaps(c, f) for f in flagged_cidrs)]
    removed_keys = set(removed)
    kept = [c for c in authorized if c not in removed_keys]
    body = "".join(f" ip4:{cidr_string(c)}" for c in kept)
    return {"removed": removed, "record": f"v=spf1{body} {config['spf_all']}"}


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #
def _is_dmarc(text: str) -> bool:
    return text.lstrip().lower().startswith("v=dmarc1")


def _norm_policy(value):
    low = (value or "").lower()
    return low if low in ("reject", "quarantine") else "none"


def _norm_align(value):
    return "s" if (value or "").lower() == "s" else "r"


def parse_dmarc(record: str) -> dict:
    tags: dict = {}
    for segment in record.split(";"):
        trimmed = segment.strip()
        eq = trimmed.find("=")
        if eq == -1:
            continue
        key = trimmed[:eq].strip().lower()
        value = trimmed[eq + 1:].strip()
        if key and key != "v" and key not in tags:
            tags[key] = value
    policy = _norm_policy(tags.get("p"))
    sp_explicit = "sp" in tags
    subdomain_policy = _norm_policy(tags.get("sp")) if sp_explicit else policy
    pct_raw = tags.get("pct", "")
    pct = int(pct_raw) if pct_raw.lstrip("-").isdigit() else 100
    return {
        "present": True, "policy": policy, "subdomain_policy": subdomain_policy,
        "sp_explicit": sp_explicit, "pct": pct, "adkim": _norm_align(tags.get("adkim")),
        "aspf": _norm_align(tags.get("aspf")), "has_rua": "rua" in tags and len(tags.get("rua") or "") > 0,
    }


def resolve_dmarc(zones: dict, domain: str) -> dict:
    _, records = _query(zones, f"_dmarc.{domain}", "TXT")
    matches = [r for r in records if _is_dmarc(r)]
    if not matches:
        return {"present": False, "policy": "none", "subdomain_policy": "none", "sp_explicit": False,
                "pct": 100, "adkim": "r", "aspf": "r", "has_rua": False}
    return parse_dmarc(matches[0])


def dmarc_weaknesses(result: dict) -> list:
    if not result["present"]:
        return ["dmarc_missing"]
    codes = set()
    if result["policy"] == "none":
        codes.add("dmarc_policy_none")
    if result["policy"] == "quarantine":
        codes.add("dmarc_policy_quarantine")
    if result["sp_explicit"] and result["subdomain_policy"] != "reject":
        codes.add("dmarc_subdomain_gap")
    if result["pct"] < 100:
        codes.add("dmarc_partial_pct")
    if result["adkim"] == "r" or result["aspf"] == "r":
        codes.add("dmarc_relaxed_alignment")
    if not result["has_rua"]:
        codes.add("dmarc_rua_missing")
    return sorted(codes)


def harden_dmarc(config: dict) -> str:
    p = config["policy"]
    return f"v=DMARC1; p={p}; sp={p}; adkim=s; aspf=s; pct=100; rua={config['rua']}"


def norm_config(raw: dict) -> dict:
    return {
        "rua": raw["rua"] if raw.get("rua") else "mailto:dmarc-reports@localhost",
        "policy": "quarantine" if raw.get("policy") == "quarantine" else "reject",
        "spf_all": raw["spf_all"] if raw.get("spf_all") else "-all",
    }


# --------------------------------------------------------------------------- #
# Oracle
# --------------------------------------------------------------------------- #
def build_oracle(scope: dict, raw_config: dict, zones: dict, probes: list, feed: list) -> dict:
    config = norm_config(raw_config)
    by_domain: dict = {}
    for p in probes:
        by_domain.setdefault(p["domain"], []).append(p)

    observations = []
    domains = []
    removed_total = 0
    for domain in scope["domains"]:
        analysis = analyze_record(zones, domain)
        passing = []
        pass_count = 0
        permerror_count = 0
        for probe in by_domain.get(domain, []):
            ev = evaluate_spf(zones, domain, probe["ip"])
            observations.append({"id": probe["id"], "domain": domain, "ip": probe["ip"],
                                 "spf_result": ev["result"], "lookups": ev["lookups"]})
            if ev["result"] == "pass":
                passing.append(probe["ip"])
                pass_count += 1
            elif ev["result"] == "permerror":
                permerror_count += 1
        hardened = harden_spf(passing, feed, config)
        removed_total += len(hardened["removed"])
        spf_weak = spf_weaknesses(analysis, permerror_count > 0, len(hardened["removed"]) > 0)
        dmarc = resolve_dmarc(zones, domain)
        domains.append({
            "domain": domain,
            "spf": {"present": analysis["present"], "effective_all": analysis["effective_all"],
                    "pass_count": pass_count, "permerror_count": permerror_count,
                    "weaknesses": spf_weak, "record": hardened["record"]},
            "dmarc": {"present": dmarc["present"], "policy": dmarc["policy"],
                      "subdomain_policy": dmarc["subdomain_policy"], "pct": dmarc["pct"],
                      "adkim": dmarc["adkim"], "aspf": dmarc["aspf"],
                      "weaknesses": dmarc_weaknesses(dmarc), "record": harden_dmarc(config)},
        })

    observations.sort(key=lambda o: o["id"])
    domains.sort(key=lambda d: d["domain"])
    spf_pass = sum(1 for o in observations if o["spf_result"] == "pass")
    spf_perm = sum(1 for o in observations if o["spf_result"] == "permerror")
    dmarc_weak = sum(1 for d in domains if d["dmarc"]["weaknesses"])

    report = {
        "generated_by": "mailguard",
        "report_version": "1",
        "observations": [
            {"id": o["id"], "domain": o["domain"], "ip": o["ip"], "spf_result": o["spf_result"], "lookups": o["lookups"]}
            for o in observations
        ],
        "domains": [
            {"domain": d["domain"],
             "spf": {"present": d["spf"]["present"], "effective_all": d["spf"]["effective_all"],
                     "pass_count": d["spf"]["pass_count"], "permerror_count": d["spf"]["permerror_count"],
                     "weaknesses": d["spf"]["weaknesses"], "hardened_record": d["spf"]["record"]},
             "dmarc": {"present": d["dmarc"]["present"], "policy": d["dmarc"]["policy"],
                       "subdomain_policy": d["dmarc"]["subdomain_policy"], "pct": d["dmarc"]["pct"],
                       "adkim": d["dmarc"]["adkim"], "aspf": d["dmarc"]["aspf"],
                       "weaknesses": d["dmarc"]["weaknesses"], "hardened_record": d["dmarc"]["record"]}}
            for d in domains
        ],
        "summary": {"observations": len(observations), "domains": len(domains),
                    "spf_pass": spf_pass, "spf_permerror": spf_perm,
                    "dmarc_weak": dmarc_weak, "flagged_sources_removed": removed_total},
    }

    artifacts = {"email-auth-report.json": canonical_json(report)}
    for d in domains:
        artifacts[f"zones/{d['domain']}/spf.txt"] = (d["spf"]["record"] + "\n").encode("utf-8")
        artifacts[f"zones/{d['domain']}/dmarc.txt"] = (d["dmarc"]["record"] + "\n").encode("utf-8")

    lines = [
        "# Email authentication hardening audit", "",
        f"Domains assessed: {len(domains)}",
        f"Observations evaluated: {len(observations)}",
        f"SPF records with weaknesses: {sum(1 for d in domains if d['spf']['weaknesses'])}",
        f"DMARC records with weaknesses: {dmarc_weak}",
        f"Flagged sources removed: {removed_total}", "",
    ]
    for d in domains:
        spf_w = ", ".join(d["spf"]["weaknesses"]) if d["spf"]["weaknesses"] else "none"
        dmarc_w = ", ".join(d["dmarc"]["weaknesses"]) if d["dmarc"]["weaknesses"] else "none"
        lines.append(f"## {d['domain']}")
        lines.append("")
        lines.append(f"SPF: effective all {d['spf']['effective_all']}, pass {d['spf']['pass_count']}, "
                     f"permerror {d['spf']['permerror_count']}, weaknesses {spf_w}")
        lines.append(f"DMARC: policy {d['dmarc']['policy']}, weaknesses {dmarc_w}")
        lines.append("")
    artifacts["email-auth-audit.md"] = "\n".join(lines).encode("utf-8")
    return artifacts


# --------------------------------------------------------------------------- #
# Fixture writers + mock servers
# --------------------------------------------------------------------------- #
def write_inputs(base_dir: str, scope: dict, probes: dict, config: dict) -> tuple:
    os.makedirs(base_dir, exist_ok=True)
    sp = os.path.join(base_dir, "scope.json")
    pp = os.path.join(base_dir, "probes.json")
    cp = os.path.join(base_dir, "config.json")
    with open(sp, "w", encoding="utf-8") as fh:
        json.dump(scope, fh)
    with open(pp, "w", encoding="utf-8") as fh:
        json.dump(probes, fh)
    with open(cp, "w", encoding="utf-8") as fh:
        json.dump(config, fh)
    return sp, pp, cp


class DnsServer:
    def __init__(self, zones: dict, port: int = 0):
        self.queried: list = []
        db = zones
        queried = self.queried

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path != "/resolve":
                    self.send_response(404)
                    self.end_headers()
                    return
                params = parse_qs(parsed.query)
                name = params.get("name", [""])[0]
                rtype = params.get("type", ["TXT"])[0]
                queried.append((name, rtype))
                zone = db.get(name)
                status = "NXDOMAIN" if zone is None else "NOERROR"
                records = zone.get(rtype, []) if zone else []
                payload = json.dumps({"name": name, "type": rtype, "status": status, "records": records}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()


class FeedServer:
    def __init__(self, sources: list, port: int = 0):
        payload = json.dumps({"sources": sources}).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                if self.path != "/v1/flagged":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- #
# Deterministic estate generator
# --------------------------------------------------------------------------- #
_FEED_POOL = ["203.0.113.0/24", "198.18.0.0/24", "192.0.2.0/24", "198.51.100.0/24"]


def _oct(rng):
    return rng.randrange(1, 254)


def generate_estate(rng) -> tuple:
    zones: dict = {}
    counter = {"n": 0}

    def fresh(kind: str) -> str:
        counter["n"] += 1
        return f"{kind}{counter['n']}.gen.example"

    feed = []
    for cidr in _FEED_POOL:
        if rng.random() < 0.6:
            feed.append({"cidr": cidr, "reason": rng.choice(["botnet", "bulletproof", "spoofer"])})
    if not feed:
        feed.append({"cidr": rng.choice(_FEED_POOL), "reason": "botnet"})

    domains = []
    probes = []
    pid = {"n": 0}

    def add_probe(domain: str, ip: str):
        pid["n"] += 1
        probes.append({"id": f"p{pid['n']:04d}", "domain": domain, "ip": ip})

    ndomains = rng.randrange(2, 4)
    for i in range(ndomains):
        domain = f"d{i}.est{rng.randrange(1000, 9999)}.example"
        while domain in domains:
            domain = f"d{i}.est{rng.randrange(1000, 9999)}.example"
        domains.append(domain)

        if rng.random() < 0.12:
            # no SPF record -> spf_missing; probes yield 'none'
            for _ in range(rng.randrange(1, 3)):
                add_probe(domain, f"{_oct(rng)}.{_oct(rng)}.{_oct(rng)}.{_oct(rng)}")
        else:
            terms = ["v=spf1"]
            match_ips = []  # ips that should match before any -all

            # own ip4 ranges (one may be a flagged network)
            for _ in range(rng.randrange(0, 2)):
                net = f"100.64.{_oct(rng)}.0/24"
                terms.append(f"ip4:{net}")
                match_ips.append(f"100.64.{net.split('.')[2]}.7")
            if rng.random() < 0.4:
                flagged_net = rng.choice([s["cidr"] for s in feed])
                base = ".".join(flagged_net.split("/")[0].split(".")[:3])
                terms.append(f"ip4:{flagged_net}")
                match_ips.append(f"{base}.9")

            # a mechanism
            if rng.random() < 0.4:
                terms.append("a")
                a_ip = f"172.31.{_oct(rng)}.{_oct(rng)}"
                zones.setdefault(domain, {})["A"] = [a_ip]
                match_ips.append(a_ip)

            # macro exists allow-list (DNSBL-style reversed IP)
            if rng.random() < 0.4:
                terms.append("exists:%{ir}.allow." + domain)
                allow_ip = f"10.{_oct(rng)}.{_oct(rng)}.{_oct(rng)}"
                rev = ".".join(reversed(allow_ip.split(".")))
                zones[f"{rev}.allow.{domain}"] = {"A": ["127.0.0.2"]}
                match_ips.append(allow_ip)

            # include with its own ip4 (include-returns-Pass)
            if rng.random() < 0.6:
                inc = fresh("inc")
                inc_net = f"192.168.{_oct(rng)}.0/24"
                zones[inc] = {"TXT": [f"v=spf1 ip4:{inc_net} -all"]}
                terms.append(f"include:{inc}")
                match_ips.append(f"192.168.{inc_net.split('.')[2]}.5")

            # sometimes force a lookup-limit permerror path
            if rng.random() < 0.22:
                for _ in range(11):
                    inc = fresh("inc")
                    zones[inc] = {"TXT": [f"v=spf1 ip4:203.0.200.{_oct(rng)}/32 -all"]}
                    terms.append(f"include:{inc}")

            # sometimes force a void-limit permerror path (exists to absent zones)
            if rng.random() < 0.15:
                for _ in range(3):
                    terms.append("exists:%{ir}.void" + str(counter["n"]) + "." + domain)
                    counter["n"] += 1

            if rng.random() < 0.18:
                terms.append("ptr")

            # closing
            roll = rng.random()
            if roll < 0.12:
                red = fresh("red")
                zones[red] = {"TXT": [f"v=spf1 ip4:100.100.{_oct(rng)}.0/24 {rng.choice(['-all', '~all', '?all'])}"]}
                terms.append(f"redirect={red}")
            elif roll < 0.24:
                pass  # no all, no redirect -> none
            else:
                terms.append(rng.choice(["-all", "~all", "?all", "+all"]))

            record = [" ".join(terms)]
            if rng.random() < 0.08:
                record.append("v=spf1 ip4:10.0.0.0/24 -all")
            zones.setdefault(domain, {})["TXT"] = record

            # probes: the crafted matching IPs plus random ones
            for ip in match_ips:
                add_probe(domain, ip)
            for _ in range(rng.randrange(2, 4)):
                add_probe(domain, f"{_oct(rng)}.{_oct(rng)}.{_oct(rng)}.{_oct(rng)}")

        # DMARC
        if rng.random() < 0.15:
            pass
        else:
            tags = ["v=DMARC1", f"p={rng.choice(['none', 'quarantine', 'reject'])}"]
            if rng.random() < 0.35:
                tags.append(f"sp={rng.choice(['none', 'quarantine', 'reject'])}")
            if rng.random() < 0.3:
                tags.append(f"pct={rng.choice([10, 50, 100])}")
            if rng.random() < 0.4:
                tags.append("adkim=s")
            if rng.random() < 0.4:
                tags.append("aspf=s")
            if rng.random() < 0.6:
                tags.append("rua=mailto:agg@reports.example")
            zones[f"_dmarc.{domain}"] = {"TXT": ["; ".join(tags)]}

    scope = {"domains": domains}
    config = {"rua": "mailto:dmarc-agg@sec.example", "policy": rng.choice(["reject", "reject", "quarantine"]), "spf_all": "-all"}
    return scope, config, zones, {"probes": probes}, feed

"""Behavioral checks for the journal quota reconciler."""
import json
import os
import subprocess
from pathlib import Path

APP = Path(os.environ.get("JOURNAL_RECONCILE_APP", "/app"))
BIN = APP / "bin/journal-reconcile"

def allocation(names, policies, total):
    out = {name: policies[name]["floor_bytes"] for name in names}
    remaining = total - sum(out.values())
    while remaining:
        active = [name for name in names if out[name] < policies[name]["cap_bytes"]]
        if not active:
            break
        weight = sum(policies[name]["weight"] for name in active)
        given = 0
        initial = remaining
        for name in active:
            p = policies[name]
            amount = min(initial * p["weight"] // weight, p["cap_bytes"] - out[name])
            out[name] += amount
            given += amount
        remaining -= given
        for name in sorted(active):
            if remaining and out[name] < policies[name]["cap_bytes"]:
                out[name] += 1
                remaining -= 1
                given += 1
        if not given:
            break
    return out

def escaped(name):
    return "".join(chr(b) if chr(b).isalnum() and b < 128 or chr(b) in "_." else f"\\x{b:02x}" for b in name.encode())

def expected(inv, pol):
    configs, filesystems, pending = {}, [], []
    ns_by_name = {n["name"]: n for n in inv["namespaces"]}
    io_domain = {f["id"]: f["io_domain"] for f in inv["filesystems"]}
    for fs in sorted(inv["filesystems"], key=lambda x: x["id"]):
        fp = pol["filesystems"][fs["id"]]
        total = min(fp["budget_bytes"], fs["capacity_bytes"] - fp["reserve_bytes"])
        names = [n for n in inv["namespaces"] if n["filesystem"] == fs["id"]]
        pool_names = sorted(fp["pools"])
        pool_alloc = allocation(pool_names, fp["pools"], total)
        alloc, pools = {}, []
        for pool_name in pool_names:
            member_names = [
                n["name"] for n in names
                if pol["namespaces"][n["name"]]["pool"] == pool_name
            ]
            member_alloc = allocation(member_names, pol["namespaces"], pool_alloc[pool_name])
            alloc.update(member_alloc)
            pool_used = sum(member_alloc.values())
            pools.append({
                "name": pool_name,
                "allocation_bytes": pool_alloc[pool_name],
                "allocated_bytes": pool_used,
                "unallocated_bytes": pool_alloc[pool_name] - pool_used,
            })
        used = sum(alloc.values())
        filesystems.append({"id": fs["id"], "allocatable_bytes": total, "allocated_bytes": used, "unallocated_bytes": total-used, "pools": pools})
        actions = []
        for n in names:
            configs[escaped(n["name"])+".conf"] = f"[Journal]\nSystemMaxUse={alloc[n['name']]}\nSystemKeepFree={fp['reserve_bytes']}\n"
            if n["usage_bytes"] > alloc[n["name"]]:
                actions.append({"namespace":n["name"],"filesystem":fs["id"],"usage_bytes":n["usage_bytes"],"target_bytes":alloc[n["name"]],"reclaim_bytes":n["usage_bytes"]-alloc[n["name"]]})
        pending.extend(actions)
    required = {a["namespace"] for a in pending}
    done, vacuum, wave = set(), [], 0
    while len(done) < len(required):
        ready = [
            a for a in pending if a["namespace"] not in done
            and all(dep not in required or dep in done for dep in ns_by_name[a["namespace"]]["vacuum_after"])
        ]
        ready.sort(key=lambda a: (-pol["namespaces"][a["namespace"]]["priority"], ns_by_name[a["namespace"]]["oldest_unix"], a["namespace"]))
        used_domains = set()
        for action in ready:
            domain = io_domain[action["filesystem"]]
            if len(used_domains) == pol["vacuum_parallelism"] or domain in used_domains:
                continue
            action["wave"] = wave
            vacuum.append(action)
            done.add(action["namespace"])
            used_domains.add(domain)
        wave += 1
    return {"filesystems":filesystems,"vacuum":vacuum}, configs

def run_case(tmp_path, inv, pol):
    ip, pp, out = tmp_path/"inventory.json", tmp_path/"policy.json", tmp_path/"out"
    ip.write_text(json.dumps(inv)); pp.write_text(json.dumps(pol))
    result = subprocess.run(
        [str(BIN), "--inventory", str(ip), "--policy", str(pp), "--output", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result, out

def assert_case(tmp_path, inv, pol):
    result, out = run_case(tmp_path, inv, pol)
    assert result.returncode == 0, result.stderr
    plan, configs = expected(inv, pol)
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    assert (out/"plan.json").read_text() == canonical
    actual = {p.name:p.read_text() for p in (out/"journald").iterdir()}
    assert actual == configs

def test_shipped_inventory_end_to_end(tmp_path):
    """The shipped multi-filesystem inventory produces the complete canonical tree."""
    inv=json.loads((APP/"data/inventory.json").read_text()); pol=json.loads((APP/"data/policy.json").read_text())
    assert_case(tmp_path, inv, pol)

def test_dynamic_caps_remainders_unicode_and_ordering(tmp_path):
    """Fresh inputs exercise cap redistribution, integer remainders, escaping, and vacuum ties."""
    inv={"filesystems":[{"id":"zfs","io_domain":"disk-a","capacity_bytes":101,"free_bytes":11}],"namespaces":[{"name":"é/x","filesystem":"zfs","usage_bytes":60,"oldest_unix":4,"vacuum_after":["alpha"]},{"name":"alpha","filesystem":"zfs","usage_bytes":50,"oldest_unix":3,"vacuum_after":[]},{"name":"beta@2","filesystem":"zfs","usage_bytes":1,"oldest_unix":3,"vacuum_after":[]}]}
    pol={"vacuum_parallelism":3,"filesystems":{"zfs":{"reserve_bytes":11,"budget_bytes":73,"pools":{"critical":{"floor_bytes":19,"cap_bytes":41,"weight":5},"tenant":{"floor_bytes":9,"cap_bytes":65,"weight":2}}}},"namespaces":{"é/x":{"pool":"critical","floor_bytes":5,"cap_bytes":17,"weight":8,"priority":2},"alpha":{"pool":"critical","floor_bytes":7,"cap_bytes":60,"weight":3,"priority":2},"beta@2":{"pool":"tenant","floor_bytes":2,"cap_bytes":50,"weight":2,"priority":8}}}
    assert_case(tmp_path,inv,pol)

def test_unallocated_capacity_when_all_caps_bind(tmp_path):
    """Capacity left after every cap is reported rather than silently reassigned."""
    inv={"filesystems":[{"id":"f","io_domain":"disk","capacity_bytes":500,"free_bytes":0}],"namespaces":[{"name":"one","filesystem":"f","usage_bytes":2,"oldest_unix":0,"vacuum_after":[]}]}
    pol={"vacuum_parallelism":1,"filesystems":{"f":{"reserve_bytes":10,"budget_bytes":400,"pools":{"capped":{"floor_bytes":50,"cap_bytes":100,"weight":1}}}},"namespaces":{"one":{"pool":"capped","floor_bytes":1,"cap_bytes":9,"weight":1,"priority":0}}}
    assert_case(tmp_path,inv,pol)

def test_pool_unused_capacity_does_not_spill_to_another_pool(tmp_path):
    """A namespace-capped pool keeps its unused assignment isolated from peer pools."""
    inv={"filesystems":[{"id":"f","io_domain":"disk","capacity_bytes":100,"free_bytes":20}],"namespaces":[{"name":"tiny","filesystem":"f","usage_bytes":30,"oldest_unix":1,"vacuum_after":[]},{"name":"hungry","filesystem":"f","usage_bytes":80,"oldest_unix":2,"vacuum_after":[]}]}
    pol={"vacuum_parallelism":2,"filesystems":{"f":{"reserve_bytes":10,"budget_bytes":90,"pools":{"hot":{"floor_bytes":40,"cap_bytes":50,"weight":1},"cold":{"floor_bytes":20,"cap_bytes":80,"weight":1}}}},"namespaces":{"tiny":{"pool":"hot","floor_bytes":5,"cap_bytes":10,"weight":1,"priority":4},"hungry":{"pool":"cold","floor_bytes":10,"cap_bytes":80,"weight":1,"priority":2}}}
    assert_case(tmp_path,inv,pol)

def test_dependency_and_io_domain_wave_scheduling(tmp_path):
    """Ready actions share waves only across I/O domains and unlock dependents later."""
    inv={"filesystems":[{"id":"a","io_domain":"shared","capacity_bytes":30,"free_bytes":5},{"id":"b","io_domain":"shared","capacity_bytes":30,"free_bytes":5},{"id":"c","io_domain":"other","capacity_bytes":30,"free_bytes":5}],"namespaces":[{"name":"leader","filesystem":"a","usage_bytes":25,"oldest_unix":3,"vacuum_after":[]},{"name":"peer","filesystem":"b","usage_bytes":25,"oldest_unix":1,"vacuum_after":[]},{"name":"parallel","filesystem":"c","usage_bytes":25,"oldest_unix":2,"vacuum_after":[]},{"name":"follower","filesystem":"c","usage_bytes":25,"oldest_unix":0,"vacuum_after":["leader"]}]}
    pol={"vacuum_parallelism":3,"filesystems":{"a":{"reserve_bytes":5,"budget_bytes":20,"pools":{"p":{"floor_bytes":10,"cap_bytes":20,"weight":1}}},"b":{"reserve_bytes":5,"budget_bytes":20,"pools":{"p":{"floor_bytes":10,"cap_bytes":20,"weight":1}}},"c":{"reserve_bytes":5,"budget_bytes":20,"pools":{"p":{"floor_bytes":10,"cap_bytes":20,"weight":1}}}},"namespaces":{"leader":{"pool":"p","floor_bytes":5,"cap_bytes":20,"weight":1,"priority":8},"peer":{"pool":"p","floor_bytes":5,"cap_bytes":20,"weight":1,"priority":7},"parallel":{"pool":"p","floor_bytes":2,"cap_bytes":10,"weight":1,"priority":6},"follower":{"pool":"p","floor_bytes":2,"cap_bytes":10,"weight":1,"priority":9}}}
    assert_case(tmp_path,inv,pol)

def test_invalid_input_preserves_existing_output(tmp_path):
    """A cross-reference or floor-fit failure exits nonzero without changing output."""
    out=tmp_path/"out"; out.mkdir(); marker=out/"keep"; marker.write_text("original")
    inv={"filesystems":[{"id":"f","io_domain":"disk","capacity_bytes":10,"free_bytes":2}],"namespaces":[{"name":"bad","filesystem":"missing","usage_bytes":1,"oldest_unix":0,"vacuum_after":[]}]}
    pol={"vacuum_parallelism":1,"filesystems":{"f":{"reserve_bytes":1,"budget_bytes":9,"pools":{"main":{"floor_bytes":1,"cap_bytes":9,"weight":1}}}},"namespaces":{"bad":{"pool":"main","floor_bytes":1,"cap_bytes":2,"weight":1,"priority":0}}}
    ip=tmp_path/"i"; pp=tmp_path/"p"; ip.write_text(json.dumps(inv)); pp.write_text(json.dumps(pol))
    r = subprocess.run(
        [str(BIN), "--inventory", str(ip), "--policy", str(pp), "--output", str(out)],
        check=False,
    )
    assert r.returncode != 0 and marker.read_text()=="original" and sorted(p.name for p in out.iterdir())==["keep"]

def test_infeasible_pool_hierarchy_preserves_existing_output(tmp_path):
    """Namespace floors above their pool floor are rejected before output replacement."""
    out=tmp_path/"out"; out.mkdir(); marker=out/"keep"; marker.write_text("original")
    inv={"filesystems":[{"id":"f","io_domain":"disk","capacity_bytes":20,"free_bytes":2}],"namespaces":[{"name":"a","filesystem":"f","usage_bytes":1,"oldest_unix":0,"vacuum_after":[]},{"name":"b","filesystem":"f","usage_bytes":1,"oldest_unix":0,"vacuum_after":[]}]}
    pol={"vacuum_parallelism":1,"filesystems":{"f":{"reserve_bytes":2,"budget_bytes":18,"pools":{"main":{"floor_bytes":5,"cap_bytes":18,"weight":1}}}},"namespaces":{"a":{"pool":"main","floor_bytes":4,"cap_bytes":8,"weight":1,"priority":0},"b":{"pool":"main","floor_bytes":4,"cap_bytes":8,"weight":1,"priority":0}}}
    ip=tmp_path/"i"; pp=tmp_path/"p"; ip.write_text(json.dumps(inv)); pp.write_text(json.dumps(pol))
    result = subprocess.run(
        [str(BIN), "--inventory", str(ip), "--policy", str(pp), "--output", str(out)],
        check=False,
    )
    assert result.returncode != 0
    assert marker.read_text() == "original"
    assert sorted(p.name for p in out.iterdir()) == ["keep"]

def test_dependency_cycle_is_rejected_before_output_creation(tmp_path):
    """A cycle in the complete vacuum dependency graph is invalid even before allocation."""
    inv={"filesystems":[{"id":"f","io_domain":"disk","capacity_bytes":20,"free_bytes":2}],"namespaces":[{"name":"a","filesystem":"f","usage_bytes":1,"oldest_unix":0,"vacuum_after":["b"]},{"name":"b","filesystem":"f","usage_bytes":1,"oldest_unix":0,"vacuum_after":["a"]}]}
    pol={"vacuum_parallelism":2,"filesystems":{"f":{"reserve_bytes":2,"budget_bytes":18,"pools":{"main":{"floor_bytes":8,"cap_bytes":18,"weight":1}}}},"namespaces":{"a":{"pool":"main","floor_bytes":4,"cap_bytes":8,"weight":1,"priority":0},"b":{"pool":"main","floor_bytes":4,"cap_bytes":8,"weight":1,"priority":0}}}
    result, out = run_case(tmp_path, inv, pol)
    assert result.returncode != 0
    assert not out.exists()

def test_rebuild_matches_repaired_sources():
    """The installed executable has been rebuilt from the compilable repaired Go sources."""
    env=os.environ.copy(); env.update({"GOPROXY":"off","GOTOOLCHAIN":"local","GOFLAGS":"-buildvcs=false"})
    subprocess.run(["go","build","-o","/tmp/rebuilt-journal-reconcile","./cmd/journal-reconcile"],cwd=APP,env=env,check=True)

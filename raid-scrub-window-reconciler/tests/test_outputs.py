"""Black-box behavioral checks for the RAID scrub-window reconciler."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

APP = Path(os.environ.get("SCRUB_WINDOW_APP", "/app"))
BIN = Path(os.environ.get("SCRUB_WINDOW_BIN", str(APP / "bin/scrub-window")))


def escape_unit(value):
    """Apply the contract's byte-oriented systemd filename escaping."""
    return "".join(
        chr(byte)
        if (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57 or byte in (95, 46))
        else f"\\x{byte:02x}"
        for byte in value.encode()
    )


def expected(inventory, policy):
    """Independently schedule due jobs and construct expected output artifacts."""
    controllers = {item["id"]: item for item in inventory["controllers"]}
    arrays = {item["name"]: item for item in inventory["arrays"]}
    due = {
        name for name, item in arrays.items()
        if item["enabled"]
        and policy["today_day"] - item["last_scrub_day"] >= policy["arrays"][name]["cadence_days"]
    }
    pending = set(due)
    placed = {}
    jobs = []
    horizon = policy["horizon_slots"]
    count = [0] * horizon
    busy = {name: [False] * horizon for name in controllers}
    watts = {
        domain: [0] * horizon
        for domain in {item["power_domain"] for item in controllers.values()}
    }
    blackout = [False] * horizon
    for begin, end in policy["blackouts"]:
        for slot in range(begin, end):
            blackout[slot] = True

    def energy_fits(domain, load_watts, start, end):
        limit = policy["energy_limits"][domain]
        for window_start in range(horizon - limit["window_slots"] + 1):
            total = sum(
                watts[domain][slot] + (load_watts if start <= slot < end else 0)
                for slot in range(window_start, window_start + limit["window_slots"])
            )
            if total > limit["max_watt_slots"]:
                return False
        return True

    for reservation in inventory["reservations"]:
        controller = controllers[reservation["controller"]]
        assert energy_fits(
            controller["power_domain"],
            reservation["load_watts"],
            reservation["start_slot"],
            reservation["end_slot"],
        )
        for slot in range(reservation["start_slot"], reservation["end_slot"]):
            assert count[slot] < policy["max_parallel"]
            assert not busy[reservation["controller"]][slot]
            assert (
                watts[controller["power_domain"]][slot] + reservation["load_watts"]
                <= policy["power_limits"][controller["power_domain"]]
            )
        for slot in range(reservation["start_slot"], reservation["end_slot"]):
            count[slot] += 1
            busy[reservation["controller"]][slot] = True
            watts[controller["power_domain"]][slot] += reservation["load_watts"]

    while pending:
        ready = [
            name for name in pending
            if all(
                dependency["array"] not in due or dependency["array"] in placed
                for dependency in arrays[name]["scrub_after"]
            )
        ]
        assert ready
        ready.sort(key=lambda name: (
            arrays[name]["deadline_slot"],
            -policy["arrays"][name]["priority"],
            name,
        ))
        name = ready[0]
        item = arrays[name]
        controller = controllers[item["controller"]]
        earliest = max(
            [item["earliest_slot"]]
            + [
                placed[dependency["array"]]["end_slot"] + dependency["gap_slots"]
                for dependency in item["scrub_after"]
                if dependency["array"] in placed
            ]
        )
        start = None
        for candidate in range(earliest, item["deadline_slot"] - item["duration_slots"] + 1):
            slots = range(candidate, candidate + item["duration_slots"])
            if all(
                not blackout[slot]
                and count[slot] < policy["max_parallel"]
                and not busy[item["controller"]][slot]
                and watts[controller["power_domain"]][slot] + item["load_watts"]
                    <= policy["power_limits"][controller["power_domain"]]
                for slot in slots
            ) and energy_fits(
                controller["power_domain"],
                item["load_watts"],
                candidate,
                candidate + item["duration_slots"],
            ):
                start = candidate
                break
        assert start is not None
        end = start + item["duration_slots"]
        for slot in range(start, end):
            count[slot] += 1
            busy[item["controller"]][slot] = True
            watts[controller["power_domain"]][slot] += item["load_watts"]
        seconds = policy["slot_minutes"] * 60
        job = {
            "array": name,
            "controller": item["controller"],
            "power_domain": controller["power_domain"],
            "timer_unit": item["timer_unit"],
            "start_slot": start,
            "end_slot": end,
            "start_unix": inventory["window_start_unix"] + start * seconds,
            "end_unix": inventory["window_start_unix"] + end * seconds,
            "load_watts": item["load_watts"],
        }
        placed[name] = job
        jobs.append(job)
        pending.remove(name)
    jobs.sort(key=lambda item: (item["start_slot"], item["array"]))
    plan = {
        "horizon_slots": horizon,
        "jobs": jobs,
        "slot_minutes": policy["slot_minutes"],
        "window_start_unix": inventory["window_start_unix"],
    }
    configs = {
        f"{escape_unit(job['timer_unit'])}.d/scrub-window.conf":
        "[Timer]\n"
        "OnCalendar=\n"
        f"OnCalendar=@{job['start_unix']}\n"
        "AccuracySec=1s\n"
        "RandomizedDelaySec=0\n"
        "Persistent=false\n"
        for job in jobs
    }
    return plan, configs


def run_case(tmp_path, inventory, policy, output=None):
    """Write a fresh input pair and invoke the installed command."""
    inventory_path = tmp_path / "inventory.json"
    policy_path = tmp_path / "policy.json"
    output = output or tmp_path / "output"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    result = subprocess.run(
        [
            str(BIN),
            "--inventory", str(inventory_path),
            "--policy", str(policy_path),
            "--output", str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    return result, output


def assert_case(tmp_path, inventory, policy):
    """Compare the complete output tree with the independent scheduler."""
    result, output = run_case(tmp_path, inventory, policy)
    assert result.returncode == 0, result.stderr
    plan, configs = expected(inventory, policy)
    assert (output / "plan.json").read_text(encoding="utf-8") == (
        json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    )
    systemd = output / "systemd"
    actual = {
        str(path.relative_to(systemd)): path.read_text(encoding="utf-8")
        for path in systemd.rglob("scrub-window.conf")
    } if systemd.exists() else {}
    assert actual == configs


def base_policy(names, horizon=12):
    """Create a compact complete policy used by dynamic fixtures."""
    return {
        "today_day": 100,
        "slot_minutes": 10,
        "horizon_slots": horizon,
        "max_parallel": 2,
        "power_limits": {"p": 300},
        "energy_limits": {"p": {"window_slots": min(4, horizon), "max_watt_slots": 1000}},
        "blackouts": [],
        "arrays": {name: {"cadence_days": 10, "priority": 1} for name in names},
    }


def test_shipped_inventory_complete_tree():
    """The shipped fleet state yields canonical plan data and exact timer drop-ins."""
    inventory = json.loads((APP / "data/inventory.json").read_text(encoding="utf-8"))
    policy = json.loads((APP / "data/policy.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as directory:
        assert_case(Path(directory), inventory, policy)


def test_dynamic_dependency_blackout_and_unicode(tmp_path):
    """Fresh names force dependency completion, blackout avoidance, and UTF-8 escaping."""
    inventory = {
        "window_start_unix": 1800000000,
        "controllers": [{"id": "c1", "power_domain": "p"}, {"id": "c2", "power_domain": "p"}],
        "arrays": [
            {"name": "先", "controller": "c1", "timer_unit": "scrub@先.timer", "enabled": True,
             "last_scrub_day": 1, "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 6,
             "load_watts": 140, "scrub_after": []},
            {"name": "after", "controller": "c2", "timer_unit": "scrub@after.timer", "enabled": True,
                 "last_scrub_day": 2, "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 9,
                 "load_watts": 140, "scrub_after": [{"array": "先", "gap_slots": 1}]},
            {"name": "peer", "controller": "c2", "timer_unit": "scrub@peer.timer", "enabled": True,
             "last_scrub_day": 3, "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 7,
             "load_watts": 140, "scrub_after": []},
        ],
        "reservations": [
            {"id": "held", "controller": "c1", "start_slot": 0, "end_slot": 1, "load_watts": 60},
        ],
    }
    policy = base_policy(["先", "after", "peer"])
    policy["blackouts"] = [[1, 2]]
    policy["arrays"]["after"]["priority"] = 9
    assert_case(tmp_path, inventory, policy)


def test_controller_parallelism_and_power_are_independent(tmp_path):
    """Placement separately enforces controller locks, global slots, and domain watts."""
    inventory = {
        "window_start_unix": 1700000000,
        "controllers": [
            {"id": "a", "power_domain": "p"},
            {"id": "b", "power_domain": "p"},
            {"id": "c", "power_domain": "q"},
        ],
        "reservations": [
            {"id": "pre", "controller": "b", "start_slot": 0, "end_slot": 1, "load_watts": 100},
        ],
        "arrays": [
            {"name": "a1", "controller": "a", "timer_unit": "a1.timer", "enabled": True, "last_scrub_day": 0,
             "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 8, "load_watts": 180, "scrub_after": []},
            {"name": "a2", "controller": "a", "timer_unit": "a2.timer", "enabled": True, "last_scrub_day": 0,
             "duration_slots": 1, "earliest_slot": 0, "deadline_slot": 9, "load_watts": 50, "scrub_after": []},
            {"name": "b1", "controller": "b", "timer_unit": "b1.timer", "enabled": True, "last_scrub_day": 0,
             "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 8, "load_watts": 150, "scrub_after": []},
            {"name": "c1", "controller": "c", "timer_unit": "c1.timer", "enabled": True, "last_scrub_day": 0,
             "duration_slots": 2, "earliest_slot": 0, "deadline_slot": 8, "load_watts": 250, "scrub_after": []},
        ],
    }
    policy = base_policy(["a1", "a2", "b1", "c1"], horizon=10)
    policy["power_limits"] = {"p": 300, "q": 260}
    policy["energy_limits"] = {
        "p": {"window_slots": 4, "max_watt_slots": 760},
        "q": {"window_slots": 4, "max_watt_slots": 1000},
    }
    assert_case(tmp_path, inventory, policy)


def test_rolling_energy_budget_delays_instantaneously_safe_job(tmp_path):
    """A reservation can force a later start through watt-slots even below the power cap."""
    inventory = {
        "window_start_unix": 1500000000,
        "controllers": [
            {"id": "reserved", "power_domain": "rack"},
            {"id": "free", "power_domain": "rack"},
        ],
        "arrays": [
            {
                "name": "energy-bound",
                "controller": "free",
                "timer_unit": "energy-bound.timer",
                "enabled": True,
                "last_scrub_day": 0,
                "duration_slots": 2,
                "earliest_slot": 0,
                "deadline_slot": 8,
                "load_watts": 120,
                "scrub_after": [],
            },
        ],
        "reservations": [
            {
                "id": "burn-in",
                "controller": "reserved",
                "start_slot": 0,
                "end_slot": 2,
                "load_watts": 150,
            },
        ],
    }
    policy = base_policy(["energy-bound"], horizon=8)
    policy["power_limits"] = {"rack": 300}
    policy["energy_limits"] = {
        "rack": {"window_slots": 4, "max_watt_slots": 539},
    }
    assert_case(tmp_path, inventory, policy)


def test_selection_order_and_due_filter_are_load_bearing(tmp_path):
    """Deadlines, priorities, lexical ties, disabled jobs, and recent jobs determine output."""
    names = ["zeta", "alpha", "\ue000", "😀", "urgent", "disabled", "recent"]
    inventory = {
        "window_start_unix": 1600000123,
        "controllers": [{"id": "only", "power_domain": "p"}],
        "arrays": [
            {"name": name, "controller": "only", "timer_unit": f"scrub@{name}.timer",
             "enabled": name != "disabled", "last_scrub_day": 96 if name == "recent" else 0,
             "duration_slots": 1, "earliest_slot": 0,
             "deadline_slot": 5 if name == "urgent" else 8,
             "load_watts": 20, "scrub_after": []}
            for name in names
        ],
        "reservations": [],
    }
    policy = base_policy(names, horizon=8)
    for name in ("zeta", "alpha", "\ue000", "😀"):
        policy["arrays"][name]["priority"] = 7
    assert_case(tmp_path, inventory, policy)


def test_stale_tree_is_replaced_and_empty_schedule_is_valid(tmp_path):
    """Success removes stale files and emits only a canonical plan when nothing is due."""
    inventory = {
        "window_start_unix": 100,
        "controllers": [{"id": "c", "power_domain": "p"}],
        "arrays": [{"name": "idle", "controller": "c", "timer_unit": "idle.timer", "enabled": False,
                    "last_scrub_day": 0, "duration_slots": 1, "earliest_slot": 0,
                    "deadline_slot": 2, "load_watts": 1, "scrub_after": []}],
        "reservations": [],
    }
    policy = base_policy(["idle"], horizon=2)
    output = tmp_path / "output"
    output.mkdir()
    (output / "stale").write_text("old", encoding="utf-8")
    result, output = run_case(tmp_path, inventory, policy, output)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in output.iterdir()) == ["plan.json"]
    assert json.loads((output / "plan.json").read_text(encoding="utf-8"))["jobs"] == []


def test_infeasible_schedule_preserves_existing_output(tmp_path):
    """A due job with no legal contiguous placement fails without touching old output."""
    inventory = {
        "window_start_unix": 100,
        "controllers": [{"id": "c", "power_domain": "p"}],
        "arrays": [{"name": "blocked", "controller": "c", "timer_unit": "blocked.timer", "enabled": True,
                    "last_scrub_day": 0, "duration_slots": 2, "earliest_slot": 0,
                    "deadline_slot": 3, "load_watts": 100, "scrub_after": []}],
        "reservations": [],
    }
    policy = base_policy(["blocked"], horizon=3)
    policy["blackouts"] = [[1, 2]]
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep").write_bytes(b"\x00original\n")
    result, _ = run_case(tmp_path, inventory, policy, output)
    assert result.returncode != 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == {"keep": b"\x00original\n"}


def test_invalid_cross_reference_and_cycle_create_nothing(tmp_path):
    """Unknown controllers and cycles in the complete graph are rejected before output."""
    inventory = {
        "window_start_unix": 100,
        "controllers": [{"id": "c", "power_domain": "p"}],
        "arrays": [
            {"name": "one", "controller": "c", "timer_unit": "one.timer", "enabled": False,
             "last_scrub_day": 0, "duration_slots": 1, "earliest_slot": 0, "deadline_slot": 3,
             "load_watts": 1, "scrub_after": [{"array": "two", "gap_slots": 0}]},
            {"name": "two", "controller": "c", "timer_unit": "two.timer", "enabled": False,
             "last_scrub_day": 0, "duration_slots": 1, "earliest_slot": 0, "deadline_slot": 3,
             "load_watts": 1, "scrub_after": [{"array": "one", "gap_slots": 0}]},
        ],
        "reservations": [],
    }
    policy = base_policy(["one", "two"], horizon=3)
    result, output = run_case(tmp_path, inventory, policy)
    assert result.returncode != 0 and not output.exists()
    inventory["arrays"][1]["scrub_after"] = []
    inventory["arrays"][0]["controller"] = "missing"
    result, output = run_case(tmp_path, inventory, policy)
    assert result.returncode != 0 and not output.exists()


def test_invalid_reservation_ledger_preserves_existing_output(tmp_path):
    """Conflicting committed reservations are rejected before replacing prior artifacts."""
    inventory = {
        "window_start_unix": 100,
        "controllers": [
            {"id": "a", "power_domain": "p"},
            {"id": "b", "power_domain": "p"},
        ],
        "arrays": [],
        "reservations": [
            {"id": "one", "controller": "a", "start_slot": 0, "end_slot": 2, "load_watts": 180},
            {"id": "two", "controller": "b", "start_slot": 0, "end_slot": 2, "load_watts": 180},
        ],
    }
    policy = base_policy([], horizon=4)
    policy["power_limits"] = {"p": 300}
    policy["energy_limits"] = {"p": {"window_slots": 2, "max_watt_slots": 1000}}
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep").write_text("unchanged", encoding="utf-8")
    result, _ = run_case(tmp_path, inventory, policy, output)
    assert result.returncode != 0
    assert {path.name: path.read_text(encoding="utf-8") for path in output.iterdir()} == {
        "keep": "unchanged",
    }


def test_policy_completeness_and_absolute_flags(tmp_path):
    """Incomplete power policy and relative CLI paths fail without creating output."""
    inventory = {
        "window_start_unix": 100,
        "controllers": [{"id": "c", "power_domain": "p"}],
        "arrays": [],
        "reservations": [],
    }
    policy = base_policy([], horizon=3)
    policy["power_limits"] = {}
    result, output = run_case(tmp_path, inventory, policy)
    assert result.returncode != 0 and not output.exists()
    policy["power_limits"] = {"p": 300}
    policy["energy_limits"] = {}
    result, output = run_case(tmp_path, inventory, policy)
    assert result.returncode != 0 and not output.exists()
    result = subprocess.run(
        [str(BIN), "--inventory", "relative.json", "--policy", "relative.json", "--output", "relative"],
        cwd=tmp_path, text=True, capture_output=True, check=False,
    )
    assert result.returncode != 0 and not (tmp_path / "relative").exists()


def test_installed_command_uses_valid_javascript_source():
    """The installed executable invokes a syntactically valid repaired JavaScript implementation."""
    subprocess.run(["node", "--check", str(APP / "src/scrub-window.mjs")], check=True)
    result = subprocess.run([str(BIN)], text=True, capture_output=True, check=False)
    assert result.returncode != 0

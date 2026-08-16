#!/usr/bin/env node
import { readFile, mkdtemp, mkdir, writeFile, rename, rm, stat } from "node:fs/promises";
import path from "node:path";

const isInt = (v) => Number.isSafeInteger(v) && v >= 0;
const fail = (message) => { throw new Error(message); };

function compareText(a, b) {
  const aa = Array.from(a, (c) => c.codePointAt(0));
  const bb = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
    if (aa[i] !== bb[i]) return aa[i] - bb[i];
  }
  return aa.length - bb.length;
}

function parseFlags(argv) {
  if (argv.length !== 8) fail("expected --inventory, --policy, and --output");
  const values = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i];
    if (!["--inventory", "--policy", "--output"].includes(key) || values[key] || argv[i + 1] === undefined) {
      fail("invalid flags");
    }
    values[key] = argv[i + 1];
  }
  for (const key of ["--inventory", "--policy", "--output"]) {
    if (!values[key] || !path.isAbsolute(values[key])) fail("paths must be absolute");
  }
  return values;
}

async function jsonFile(filename) {
  const value = JSON.parse(await readFile(filename, "utf8"));
  if (!value || Array.isArray(value) || typeof value !== "object") fail("JSON root must be an object");
  return value;
}

function exactKeys(object, expected, label) {
  if (!object || Array.isArray(object) || typeof object !== "object") fail(`${label} must be an object`);
  const actual = Object.keys(object).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (actual.length !== wanted.length || actual.some((v, i) => v !== wanted[i])) fail(`${label} keys mismatch`);
}

function validate(inventory, policy) {
  if (!isInt(inventory.window_start_unix)) fail("bad window start");
  if (!Array.isArray(inventory.controllers) || inventory.controllers.length === 0 ||
      !Array.isArray(inventory.arrays) || !Array.isArray(inventory.reservations)) fail("bad inventory");
  const controllers = new Map();
  const domains = new Set();
  for (const controller of inventory.controllers) {
    if (!controller || typeof controller.id !== "string" || !controller.id || typeof controller.power_domain !== "string" || !controller.power_domain || controllers.has(controller.id)) fail("bad controller");
    controllers.set(controller.id, controller);
    domains.add(controller.power_domain);
  }
  const arrays = new Map();
  const units = new Set();
  for (const array of inventory.arrays) {
    if (!array || typeof array.name !== "string" || !array.name || arrays.has(array.name) ||
        typeof array.timer_unit !== "string" || !array.timer_unit || units.has(array.timer_unit) ||
        !controllers.has(array.controller) || typeof array.enabled !== "boolean" ||
        !isInt(array.last_scrub_day) || !isInt(array.duration_slots) || array.duration_slots === 0 ||
        !isInt(array.earliest_slot) || !isInt(array.deadline_slot) ||
        !isInt(array.load_watts) || array.load_watts === 0 || !Array.isArray(array.scrub_after)) fail("bad array");
    if (array.scrub_after.some((dependency) =>
      !dependency || typeof dependency !== "object" || Array.isArray(dependency) ||
      typeof dependency.array !== "string" || dependency.array === array.name ||
      !isInt(dependency.gap_slots)) ||
      new Set(array.scrub_after.map((dependency) => dependency.array)).size !== array.scrub_after.length) {
      fail("bad dependency list");
    }
    arrays.set(array.name, array);
    units.add(array.timer_unit);
  }
  if (!isInt(policy.today_day) || !isInt(policy.slot_minutes) || policy.slot_minutes === 0 ||
      !isInt(policy.horizon_slots) || policy.horizon_slots === 0 ||
      !isInt(policy.max_parallel) || policy.max_parallel === 0 ||
      !Array.isArray(policy.blackouts)) fail("bad policy");
  exactKeys(policy.power_limits, domains, "power limits");
  for (const limit of Object.values(policy.power_limits)) if (!isInt(limit) || limit === 0) fail("bad power limit");
  exactKeys(policy.energy_limits, domains, "energy limits");
  for (const limit of Object.values(policy.energy_limits)) {
    if (!limit || typeof limit !== "object" || Array.isArray(limit) ||
        !isInt(limit.window_slots) || limit.window_slots === 0 || limit.window_slots > policy.horizon_slots ||
        !isInt(limit.max_watt_slots) || limit.max_watt_slots === 0) fail("bad energy limit");
  }
  exactKeys(policy.arrays, arrays.keys(), "array policy");
  for (const [name, array] of arrays) {
    const rule = policy.arrays[name];
    if (!rule || !isInt(rule.cadence_days) || rule.cadence_days === 0 || !Number.isSafeInteger(rule.priority)) fail("bad array policy");
    if (!(array.earliest_slot < array.deadline_slot && array.deadline_slot <= policy.horizon_slots &&
          array.duration_slots <= array.deadline_slot - array.earliest_slot)) fail("bad array bounds");
    for (const dependency of array.scrub_after) if (!arrays.has(dependency.array)) fail("unknown dependency");
  }
  for (const interval of policy.blackouts) {
    if (!Array.isArray(interval) || interval.length !== 2 || !isInt(interval[0]) || !isInt(interval[1]) ||
        !(interval[0] < interval[1] && interval[1] <= policy.horizon_slots)) fail("bad blackout");
  }
  const reservations = new Map();
  for (const reservation of inventory.reservations) {
    if (!reservation || typeof reservation !== "object" || Array.isArray(reservation) ||
        typeof reservation.id !== "string" || !reservation.id || reservations.has(reservation.id) ||
        !controllers.has(reservation.controller) || !isInt(reservation.start_slot) ||
        !isInt(reservation.end_slot) || !(reservation.start_slot < reservation.end_slot) ||
        reservation.end_slot > policy.horizon_slots || !isInt(reservation.load_watts) ||
        reservation.load_watts === 0) fail("bad reservation");
    reservations.set(reservation.id, reservation);
  }
  const visiting = new Set();
  const visited = new Set();
  function visit(name) {
    if (visiting.has(name)) fail("dependency cycle");
    if (visited.has(name)) return;
    visiting.add(name);
    for (const dependency of arrays.get(name).scrub_after) visit(dependency.array);
    visiting.delete(name);
    visited.add(name);
  }
  for (const name of arrays.keys()) visit(name);
  return { controllers, arrays, reservations };
}

function schedule(inventory, policy, model) {
  const due = new Set();
  for (const [name, array] of model.arrays) {
    if (array.enabled && policy.today_day - array.last_scrub_day >= policy.arrays[name].cadence_days) due.add(name);
  }
  const pending = new Set(due);
  const byName = new Map();
  const jobs = [];
  const parallel = Array(policy.horizon_slots).fill(0);
  const controllerBusy = new Map([...model.controllers.keys()].map((id) => [id, Array(policy.horizon_slots).fill(false)]));
  const domainWatts = new Map([...new Set([...model.controllers.values()].map((c) => c.power_domain))]
    .map((domain) => [domain, Array(policy.horizon_slots).fill(0)]));
  const blackout = Array(policy.horizon_slots).fill(false);
  for (const [start, end] of policy.blackouts) for (let slot = start; slot < end; slot++) blackout[slot] = true;

  function energyFits(domain, watts, start, end) {
    const ledger = domainWatts.get(domain);
    const limit = policy.energy_limits[domain];
    for (let windowStart = 0; windowStart + limit.window_slots <= policy.horizon_slots; windowStart++) {
      let total = 0;
      for (let slot = windowStart; slot < windowStart + limit.window_slots; slot++) {
        total += ledger[slot] + (slot >= start && slot < end ? watts : 0);
      }
      if (total > limit.max_watt_slots) return false;
    }
    return true;
  }

  for (const reservation of model.reservations.values()) {
    const controller = model.controllers.get(reservation.controller);
    if (!energyFits(controller.power_domain, reservation.load_watts,
      reservation.start_slot, reservation.end_slot)) fail("reservation energy conflict");
    for (let slot = reservation.start_slot; slot < reservation.end_slot; slot++) {
      if (parallel[slot] >= policy.max_parallel || controllerBusy.get(reservation.controller)[slot] ||
          domainWatts.get(controller.power_domain)[slot] + reservation.load_watts >
            policy.power_limits[controller.power_domain]) fail("reservation resource conflict");
    }
    for (let slot = reservation.start_slot; slot < reservation.end_slot; slot++) {
      parallel[slot]++;
      controllerBusy.get(reservation.controller)[slot] = true;
      domainWatts.get(controller.power_domain)[slot] += reservation.load_watts;
    }
  }

  while (pending.size) {
    const ready = [...pending].filter((name) => model.arrays.get(name).scrub_after
      .every((dependency) => !due.has(dependency.array) || byName.has(dependency.array)));
    if (!ready.length) fail("no ready job");
    ready.sort((a, b) => {
      const aa = model.arrays.get(a);
      const bb = model.arrays.get(b);
      return aa.deadline_slot - bb.deadline_slot ||
        policy.arrays[b].priority - policy.arrays[a].priority || compareText(a, b);
    });
    const name = ready[0];
    const array = model.arrays.get(name);
    const controller = model.controllers.get(array.controller);
    let earliest = array.earliest_slot;
    for (const dependency of array.scrub_after) {
      if (byName.has(dependency.array)) {
        earliest = Math.max(earliest, byName.get(dependency.array).end_slot + dependency.gap_slots);
      }
    }
    let start = -1;
    for (let candidate = earliest; candidate + array.duration_slots <= array.deadline_slot; candidate++) {
      let fits = true;
      for (let slot = candidate; slot < candidate + array.duration_slots; slot++) {
        if (blackout[slot] || parallel[slot] >= policy.max_parallel ||
            controllerBusy.get(array.controller)[slot] ||
            domainWatts.get(controller.power_domain)[slot] + array.load_watts > policy.power_limits[controller.power_domain]) {
          fits = false;
          break;
        }
      }
      if (fits && energyFits(controller.power_domain, array.load_watts,
        candidate, candidate + array.duration_slots)) {
        start = candidate;
        break;
      }
    }
    if (start < 0) fail(`infeasible job: ${name}`);
    const end = start + array.duration_slots;
    for (let slot = start; slot < end; slot++) {
      parallel[slot]++;
      controllerBusy.get(array.controller)[slot] = true;
      domainWatts.get(controller.power_domain)[slot] += array.load_watts;
    }
    const seconds = policy.slot_minutes * 60;
    const job = {
      array: name,
      controller: array.controller,
      power_domain: controller.power_domain,
      timer_unit: array.timer_unit,
      start_slot: start,
      end_slot: end,
      start_unix: inventory.window_start_unix + start * seconds,
      end_unix: inventory.window_start_unix + end * seconds,
      load_watts: array.load_watts
    };
    jobs.push(job);
    byName.set(name, job);
    pending.delete(name);
  }
  jobs.sort((a, b) => a.start_slot - b.start_slot || compareText(a.array, b.array));
  return jobs;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort(compareText)) out[key] = canonical(value[key]);
    return out;
  }
  return value;
}

function escaped(value) {
  let out = "";
  for (const byte of Buffer.from(value, "utf8")) {
    const literal = (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
      (byte >= 48 && byte <= 57) || byte === 95 || byte === 46;
    out += literal ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, "0")}`;
  }
  return out;
}

async function exists(filename) {
  try { await stat(filename); return true; } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function writeTree(output, inventory, policy, jobs) {
  const parent = path.dirname(output);
  await mkdir(parent, { recursive: true });
  const temporary = await mkdtemp(path.join(parent, ".scrub-window-"));
  const backup = path.join(parent, `.scrub-window-backup-${process.pid}`);
  let movedOld = false;
  try {
    const plan = {
      horizon_slots: policy.horizon_slots,
      slot_minutes: policy.slot_minutes,
      window_start_unix: inventory.window_start_unix,
      jobs
    };
    await writeFile(path.join(temporary, "plan.json"), JSON.stringify(canonical(plan)) + "\n");
    for (const job of jobs) {
      const directory = path.join(temporary, "systemd", `${escaped(job.timer_unit)}.d`);
      await mkdir(directory, { recursive: true });
      const content = `[Timer]\nOnCalendar=\nOnCalendar=@${job.start_unix}\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=false\n`;
      await writeFile(path.join(directory, "scrub-window.conf"), content);
    }
    if (await exists(output)) {
      if (await exists(backup)) fail("backup path collision");
      await rename(output, backup);
      movedOld = true;
    }
    try {
      await rename(temporary, output);
    } catch (error) {
      if (movedOld) await rename(backup, output);
      throw error;
    }
    if (movedOld) await rm(backup, { recursive: true, force: true }).catch(() => {});
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

async function main() {
  const flags = parseFlags(process.argv);
  const inventory = await jsonFile(flags["--inventory"]);
  const policy = await jsonFile(flags["--policy"]);
  const model = validate(inventory, policy);
  const jobs = schedule(inventory, policy, model);
  await writeTree(flags["--output"], inventory, policy, jobs);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});

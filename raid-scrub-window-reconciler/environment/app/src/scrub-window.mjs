#!/usr/bin/env node
import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

function flags(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) out[argv[i]] = argv[i + 1];
  return out;
}

async function main() {
  const f = flags(process.argv);
  const inventory = JSON.parse(await readFile(f["--inventory"], "utf8"));
  const policy = JSON.parse(await readFile(f["--policy"], "utf8"));
  await mkdir(f["--output"], { recursive: true });
  const jobs = [];
  for (const array of inventory.arrays) {
    const rule = policy.arrays[array.name];
    if (!array.enabled || policy.today_day - array.last_scrub_day < rule.cadence_days) continue;
    const start = array.earliest_slot;
    jobs.push({
      array: array.name,
      controller: array.controller,
      timer_unit: array.timer_unit,
      start_slot: start,
      end_slot: start + array.duration_slots
    });
  }
  await writeFile(path.join(f["--output"], "plan.json"), JSON.stringify({ jobs }) + "\n");
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});

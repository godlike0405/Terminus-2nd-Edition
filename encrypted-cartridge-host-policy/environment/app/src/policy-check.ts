import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[2] ?? "/";
const required = [
  "etc/sysusers.d/archive-cartridge.conf",
  "etc/tmpfiles.d/archive-cartridge.conf",
  "etc/udev/rules.d/70-archive-cartridge.rules",
  "etc/systemd/system/archive-cartridge@.service",
  "etc/systemd/system/archive-cartridge-quarantine@.service",
  "etc/systemd/system/archive-cartridge.slice",
  "etc/logrotate.d/archive-cartridge",
];
const missing = required.filter((name) => !existsSync(join(root, name)));
if (missing.length > 0) {
  process.stderr.write(`missing: ${missing.join(", ")}\n`);
  process.exit(1);
}
const unit = readFileSync(
  join(root, "etc/systemd/system/archive-cartridge@.service"),
  "utf8",
);
const systemdRoot = join(root, "etc/systemd/system");
const profilePolicy = missing.length === 0
  ? readFileSync(join(root, "etc/udev/rules.d/70-archive-cartridge.rules"), "utf8")
  : "";
for (const term of [
  "ExecStart=",
  "ExecStopPost=-",
  "ProtectSystem=strict",
  "CapabilityBoundingSet=CAP_SYS_ADMIN",
  "exec /usr/bin/setpriv --bounding-set=-all",
  "OnFailure=archive-cartridge-quarantine@%i.service",
  "ConditionPathExists=!",
]) {
  if (!unit.includes(term)) {
    process.stderr.write(`unit lacks ${term}\n`);
    process.exit(1);
  }
}
if (!profilePolicy.includes("archive-cartridge@")) {
  process.stderr.write("udev policy has no cartridge instances\n");
  process.exit(1);
}
const inventory = JSON.parse(
  readFileSync(new URL("../data/cartridges.json", import.meta.url), "utf8"),
) as { cartridges: Array<{ profile: string }> };
for (const row of inventory.cartridges) {
  const dropin = readFileSync(
    join(
      systemdRoot,
      `archive-cartridge@${row.profile}.service.d/10-cartridge.conf`,
    ),
    "utf8",
  );
  if (!dropin.includes("LoadCredential=luks.key:")) {
    process.stderr.write(`profile ${row.profile} lacks encrypted credential\n`);
    process.exit(1);
  }
  for (const term of [
    "Slice=archive-cartridge.slice",
    "MemoryMax=",
    "LimitFSIZE=",
    "StartLimitBurst=",
  ]) {
    if (!dropin.includes(term)) {
      process.stderr.write(`profile ${row.profile} lacks ${term}\n`);
      process.exit(1);
    }
  }
}
const quarantine = readFileSync(
  join(systemdRoot, "archive-cartridge-quarantine@.service"),
  "utf8",
);
for (const term of [
  "Type=oneshot",
  "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER",
  "/quarantine/%i.blocked",
]) {
  if (!quarantine.includes(term)) {
    process.stderr.write(`quarantine unit lacks ${term}\n`);
    process.exit(1);
  }
}
process.stdout.write("policy: ok\n");

import { readFileSync } from "node:fs";

type Cartridge = {
  profile: string;
  luksUuid: string;
  filesystemUuid: string;
  mapping: string;
  credential: string;
  deviceSerial: string;
  mountOptions: string[];
  maxRuntimeSeconds: number;
  ioWeight: number;
};

type Inventory = {
  account: string;
  group: string;
  worker: string;
  source: string;
  lock: string;
  logDirectory: string;
  stateDirectory: string;
  mountRoot: string;
  cartridges: Cartridge[];
};

const file = new URL("../data/cartridges.json", import.meta.url);
const inventory = JSON.parse(readFileSync(file, "utf8")) as Inventory;
process.stdout.write(`${JSON.stringify(inventory)}\n`);

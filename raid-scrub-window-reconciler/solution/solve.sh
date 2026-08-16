#!/bin/bash
set -euo pipefail

cd /app
cp /solution/scrub-window.mjs /app/src/scrub-window.mjs
chmod +x /app/src/scrub-window.mjs /app/bin/scrub-window
npm run check

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
/app/bin/scrub-window \
  --inventory /app/data/inventory.json \
  --policy /app/data/policy.json \
  --output "$workdir/output"
node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1])); if (!Array.isArray(p.jobs)) process.exit(1)' "$workdir/output/plan.json"

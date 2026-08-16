#!/usr/bin/env bash
set -uo pipefail

if [ "$PWD" = "/" ]; then
    echo "Error: No working directory set." >&2
    mkdir -p /logs/verifier
    echo 0 > /logs/verifier/reward.txt
    exit 0
fi

mkdir -p /logs/verifier
echo 0 > /logs/verifier/reward.txt

# Recompile whatever TypeScript the agent left behind into /app/dist. The
# TypeScript compiler and all dependencies are baked into the image; nothing is
# fetched from the network here.
npm --prefix /app run build

# pytest and pytest-json-ctrf are pre-installed in the image via the Dockerfile.
python3 -m pytest -o cache_dir=/tmp/pytest_cache --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
rc=$?

if [ "$rc" -eq 0 ]; then
    echo 1 > /logs/verifier/reward.txt
else
    echo 0 > /logs/verifier/reward.txt
fi

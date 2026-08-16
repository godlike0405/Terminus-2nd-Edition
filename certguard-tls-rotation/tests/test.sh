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

# Remove any previously built binary first so a failed build can never leave a
# stale artifact for the tests to run against, then rebuild whatever Go sources
# the agent left behind. The Go toolchain is baked into the image and the module
# has no external dependencies; nothing is fetched from the network here.
rm -f /app/bin/certguard
if ! (cd /app && go build -o bin/certguard ./cmd/certguard); then
    echo "go build failed; refusing to run tests against a stale or missing binary" >&2
    echo 0 > /logs/verifier/reward.txt
    exit 0
fi

# pytest and pytest-json-ctrf are pre-installed in the image via the Dockerfile.
python3 -m pytest -o cache_dir=/tmp/pytest_cache --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
rc=$?

if [ "$rc" -eq 0 ]; then
    echo 1 > /logs/verifier/reward.txt
else
    echo 0 > /logs/verifier/reward.txt
fi

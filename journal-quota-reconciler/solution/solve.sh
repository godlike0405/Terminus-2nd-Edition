#!/bin/bash
set -euo pipefail
cp /solution/main.go /app/cmd/journal-reconcile/main.go
cd /app
gofmt -w cmd/journal-reconcile/main.go
go build -o /app/bin/journal-reconcile ./cmd/journal-reconcile

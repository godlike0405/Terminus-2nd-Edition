// Command certguard reads a host's TLS inventory, validates each service's
// certificate chain against the trust store and revocation service, and writes
// the rotation, block, report and audit artifacts described in
// /app/docs/cert-spec.md.
package main

import (
	"fmt"
	"os"

	"certguard/internal/decide"
	"certguard/internal/model"
	"certguard/internal/report"
	"certguard/internal/revoke"
)

func env(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

func run() error {
	invDir := env("INVENTORY_DIR", "/app/data/inventory")
	base := env("REVOCATION_API_BASE", "http://127.0.0.1:8730")
	outDir := env("OUTPUT_DIR", "/app/out")

	inv, err := model.LoadInventory(invDir)
	if err != nil {
		return err
	}
	evalTime, err := model.ParseTime(inv.Policy.EvaluatedAt)
	if err != nil {
		return fmt.Errorf("policy evaluated_at: %w", err)
	}
	rev := revoke.New(base)
	results, err := decide.Evaluate(inv, rev, evalTime, inv.Policy.RotationWindowDays)
	if err != nil {
		return err
	}
	return report.WriteArtifacts(outDir, inv.Policy.EvaluatedAt, results)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "certguard:", err)
		os.Exit(1)
	}
}

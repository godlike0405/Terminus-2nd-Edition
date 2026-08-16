// Package report renders certguard's artifacts: nginx rotation snippets, systemd
// override drop-ins, the canonical JSON trust report and the Markdown audit note.
package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"certguard/internal/canon"
	"certguard/internal/decide"
)

const systemdOverride = "[Service]\nExecStart=\nExecStart=/bin/false\nNoNewPrivileges=yes\nProtectSystem=strict\n"

func fphex(fingerprint string) string {
	return strings.TrimPrefix(fingerprint, "sha256:")
}

func writeFile(outDir, rel, contents string) error {
	full := filepath.Join(outDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, []byte(contents), 0o644)
}

func nullable(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func chainArray(chain []string) []any {
	out := make([]any, 0, len(chain))
	for _, fp := range chain {
		out = append(out, fp)
	}
	return out
}

// WriteArtifacts writes every artifact for the evaluated services under outDir.
func WriteArtifacts(outDir, evaluatedAt string, results []decide.ServiceResult) error {
	services := make([]any, 0, len(results))
	rotations := make([]any, 0)
	blocked := make([]any, 0)

	for _, r := range results {
		services = append(services, map[string]any{
			"unit":                    r.Unit,
			"server_name":             r.ServerName,
			"enabled":                 r.Enabled,
			"bound_id":                r.BoundID,
			"decision":                r.Decision,
			"reason":                  r.Reason,
			"anchored":                r.Anchored,
			"bound_fingerprint":       nullable(r.BoundFingerprint),
			"bound_not_after":         nullable(r.BoundNotAfter),
			"chain":                   chainArray(r.Chain),
			"replacement_fingerprint": nullable(r.ReplacementFingerprint),
		})

		switch r.Decision {
		case "rotate":
			hex := fphex(*r.ReplacementFingerprint)
			snippet := "# certguard: rotated " + r.Unit + " (" + r.Reason + ")\n" +
				"ssl_certificate     /etc/certguard/certs/" + hex + ".pem;\n" +
				"ssl_certificate_key /etc/certguard/private/" + hex + ".key;\n"
			if err := writeFile(outDir, "nginx/"+r.Unit+".conf", snippet); err != nil {
				return err
			}
			rotations = append(rotations, map[string]any{"unit": r.Unit, "fingerprint": *r.ReplacementFingerprint})
		case "block":
			if err := writeFile(outDir, "systemd/"+r.Unit+"/override.conf", systemdOverride); err != nil {
				return err
			}
			blocked = append(blocked, r.Unit)
		}
	}

	report := map[string]any{
		"generated_by":   "certguard",
		"report_version": "1",
		"evaluated_at":   evaluatedAt,
		"services":       services,
		"rotations":      rotations,
		"blocked_units":  blocked,
	}
	if err := writeFile(outDir, "tls-trust-report.json", string(canon.WithNewline(report))); err != nil {
		return err
	}

	return writeFile(outDir, "tls-rotation-audit.md", renderMarkdown(evaluatedAt, results))
}

func renderMarkdown(evaluatedAt string, results []decide.ServiceResult) string {
	rotated, blocked, compliant := 0, 0, 0
	for _, r := range results {
		switch r.Decision {
		case "rotate":
			rotated++
		case "block":
			blocked++
		case "ok":
			compliant++
		}
	}
	lines := []string{
		"# TLS service rotation audit",
		"",
		"Evaluated at: " + evaluatedAt,
		"Services scanned: " + strconv.Itoa(len(results)),
		"Rotated: " + strconv.Itoa(rotated),
		"Blocked: " + strconv.Itoa(blocked),
		"Compliant: " + strconv.Itoa(compliant),
		"",
	}
	for _, r := range results {
		chainStr := "none"
		if len(r.Chain) > 0 {
			hexes := make([]string, 0, len(r.Chain))
			for _, fp := range r.Chain {
				hexes = append(hexes, fphex(fp))
			}
			chainStr = strings.Join(hexes, " > ")
		}
		var verdict string
		switch r.Decision {
		case "rotate":
			verdict = "ROTATED to " + fphex(*r.ReplacementFingerprint)
		case "block":
			verdict = "BLOCKED (" + r.Reason + ")"
		default:
			verdict = "COMPLIANT"
		}
		lines = append(lines,
			"## "+r.Unit,
			"",
			"- Server name: "+r.ServerName,
			"- Bound certificate: "+r.BoundID,
			"- Chain: "+chainStr,
			"- Decision: "+verdict,
			"",
		)
	}
	return strings.Join(lines, "\n")
}

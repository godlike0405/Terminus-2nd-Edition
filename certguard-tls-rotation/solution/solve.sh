#!/usr/bin/env bash
set -euo pipefail

# Rewrites the four incomplete modules so certguard builds each service's
# certificate chain to a trusted anchor, validates it (validity, path length,
# extended key usage, server identity and name constraints), applies CRL
# revocation with currency and removeFromCRL semantics, selects the correct
# replacement, and writes the artifacts at the paths the contract requires.
# The remaining packages are already correct.

cd "${APP_DIR:-/app}"

cat > internal/chain/chain.go <<'EOF_chain'
// Package chain builds a certificate's issuer chain up to a trusted anchor and
// checks the chain's structural validity (issuance, validity window, path length,
// extended key usage, server identity and name constraints).
package chain

import (
	"strings"
	"time"

	"certguard/internal/model"
)

// Build follows issuers from leaf (subject_key_id == authority_key_id linkage)
// up to the first trusted anchor. It returns the chain leaf..anchor and whether
// an anchor was reached. Subject key ids are unique, so the chain is unique.
func Build(inv *model.Inventory, leaf *model.Certificate) (chain []*model.Certificate, anchored bool) {
	chain = []*model.Certificate{leaf}
	seen := map[string]bool{leaf.SubjectKeyID: true}
	current := leaf
	for {
		if inv.IsAnchor(current.SubjectKeyID) {
			return chain, true
		}
		if current.AuthorityKeyID == current.SubjectKeyID {
			return chain, false
		}
		issuer := inv.BySKI(current.AuthorityKeyID)
		if issuer == nil || seen[issuer.SubjectKeyID] {
			return chain, false
		}
		seen[issuer.SubjectKeyID] = true
		chain = append(chain, issuer)
		current = issuer
	}
}

func contains(items []string, want string) bool {
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}

// sanMatch reports whether a SAN entry covers name (case-insensitive). A leading
// "*." wildcard matches exactly one left label.
func sanMatch(san, name string) bool {
	san = strings.ToLower(san)
	name = strings.ToLower(name)
	if strings.HasPrefix(san, "*.") {
		suffix := san[2:]
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return false
		}
		return name[dot+1:] == suffix
	}
	return san == name
}

// subtreeMatch reports whether a DNS name falls under a name-constraint subtree.
func subtreeMatch(name, subtree string) bool {
	name = strings.ToLower(name)
	subtree = strings.ToLower(subtree)
	return name == subtree || strings.HasSuffix(name, "."+subtree)
}

// ServerIdentityOK reports whether the leaf's SANs cover serverName.
func ServerIdentityOK(leaf *model.Certificate, serverName string) bool {
	for _, san := range leaf.SANs {
		if sanMatch(san, serverName) {
			return true
		}
	}
	return false
}

// ValidateStructure reports whether chain is structurally valid as of t for a
// service identified by serverName. Revocation is checked separately.
func ValidateStructure(inv *model.Inventory, chain []*model.Certificate, serverName string, t time.Time) bool {
	n := len(chain) - 1
	if n < 0 || !inv.IsAnchor(chain[n].SubjectKeyID) {
		return false // rule 1: anchored
	}
	for i, cert := range chain {
		// rule 2: issuance
		if i > 0 && (!cert.IsCA || !contains(cert.KeyUsages, "certSign")) {
			return false
		}
		// rule 3: validity for every cert except the anchor
		if i < n {
			if t.Before(cert.NotBeforeT()) || t.After(cert.NotAfterT()) {
				return false
			}
		}
		// rule 4: path length
		if i >= 1 && cert.PathLen != nil && (i-1) > *cert.PathLen {
			return false
		}
		// rule 5: extended key usage (every cert on the chain)
		if len(cert.ExtKeyUsages) > 0 &&
			!contains(cert.ExtKeyUsages, "serverAuth") &&
			!contains(cert.ExtKeyUsages, "anyExtendedKeyUsage") {
			return false
		}
		// rule 7: name constraints on CAs above the leaf
		if i >= 1 && cert.NameConstraints != nil {
			nc := cert.NameConstraints
			if len(nc.Permitted) > 0 {
				ok := false
				for _, sub := range nc.Permitted {
					if subtreeMatch(serverName, sub) {
						ok = true
						break
					}
				}
				if !ok {
					return false
				}
			}
			for _, sub := range nc.Excluded {
				if subtreeMatch(serverName, sub) {
					return false
				}
			}
		}
	}
	// rule 6: server identity
	return ServerIdentityOK(chain[0], serverName)
}
EOF_chain

cat > internal/revoke/revoke.go <<'EOF_revoke'
// Package revoke consults the revocation service and decides whether a
// certificate is revoked as of the evaluation instant, following CRL currency
// (fail-closed on a stale CRL) and removeFromCRL semantics.
package revoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"certguard/internal/model"
)

// CRLEntry is one revocation record.
type CRLEntry struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

// CRL is a certificate revocation list for one issuer.
type CRL struct {
	IssuerKeyID string     `json:"issuer_key_id"`
	ThisUpdate  string     `json:"this_update"`
	NextUpdate  string     `json:"next_update"`
	Entries     []CRLEntry `json:"entries"`
}

type response struct {
	CRL *CRL `json:"crl"`
}

// Revoker queries and caches CRLs from the revocation service.
type Revoker struct {
	base    string
	client  *http.Client
	cache   map[string]*CRL
	fetched map[string]bool
}

// New builds a Revoker pointed at the revocation service base URL.
func New(base string) *Revoker {
	transport := &http.Transport{DisableKeepAlives: true}
	return &Revoker{
		base:    base,
		client:  &http.Client{Timeout: 30 * time.Second, Transport: transport},
		cache:   map[string]*CRL{},
		fetched: map[string]bool{},
	}
}

// crlFor fetches (and caches) the CRL for an issuer key id; a nil CRL means the
// issuer publishes no revocation data.
func (r *Revoker) crlFor(issuerKeyID string) (*CRL, error) {
	if r.fetched[issuerKeyID] {
		return r.cache[issuerKeyID], nil
	}
	body, err := json.Marshal(map[string]string{"issuer_key_id": issuerKeyID})
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Post(r.base+"/v1/revocations", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation query for %s: status %d", issuerKeyID, resp.StatusCode)
	}
	var parsed response
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("revocation query for %s: %w", issuerKeyID, err)
	}
	r.cache[issuerKeyID] = parsed.CRL
	r.fetched[issuerKeyID] = true
	return parsed.CRL, nil
}

// CertRevoked reports whether cert is revoked as of t according to its issuer's
// CRL. No CRL means not revoked; a stale CRL fails closed (revoked).
func (r *Revoker) CertRevoked(cert *model.Certificate, t time.Time) (bool, error) {
	crl, err := r.crlFor(cert.AuthorityKeyID)
	if err != nil {
		return false, err
	}
	if crl == nil {
		return false, nil
	}
	thisUpdate, err := model.ParseTime(crl.ThisUpdate)
	if err != nil {
		return false, err
	}
	nextUpdate, err := model.ParseTime(crl.NextUpdate)
	if err != nil {
		return false, err
	}
	if t.Before(thisUpdate) || t.After(nextUpdate) {
		return true, nil // stale CRL: status unknown, fail closed
	}
	want, err := model.SerialValue(cert.Serial)
	if err != nil {
		return false, err
	}
	for _, entry := range crl.Entries {
		if entry.Reason == "removeFromCRL" {
			continue
		}
		got, err := model.SerialValue(entry.Serial)
		if err != nil {
			return false, err
		}
		if got.Cmp(want) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// ChainRevoked reports whether any non-anchor certificate on chain is revoked.
// Every non-anchor certificate's issuer CRL is consulted — the query set depends
// only on chain linkage, not on an early revoked result — so it does not stop at
// the first revoked certificate.
func (r *Revoker) ChainRevoked(chain []*model.Certificate, t time.Time) (bool, error) {
	revoked := false
	for i := 0; i < len(chain)-1; i++ {
		got, err := r.CertRevoked(chain[i], t)
		if err != nil {
			return false, err
		}
		if got {
			revoked = true
		}
	}
	return revoked, nil
}
EOF_revoke

cat > internal/decide/decide.go <<'EOF_decide'
// Package decide runs the per-service classification and replacement selection
// that certguard's decision policy requires.
package decide

import (
	"sort"
	"time"

	"certguard/internal/chain"
	"certguard/internal/model"
	"certguard/internal/revoke"
)

// ServiceResult is the evaluated outcome for one service; it carries every field
// the report and audit note need.
type ServiceResult struct {
	Unit                   string
	ServerName             string
	Enabled                bool
	BoundID                string
	Decision               string // "ok", "rotate", "block"
	Reason                 string
	Anchored               bool
	BoundFingerprint       *string
	BoundNotAfter          *string
	Chain                  []string // leaf..anchor fingerprints, empty when no bound chain
	ReplacementFingerprint *string
}

type leafEval struct {
	chain    []*model.Certificate
	anchored bool
	structOK bool
	revoked  bool
}

func fingerprints(certs []*model.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Fingerprint())
	}
	return out
}

func strptr(s string) *string { return &s }

// Evaluate classifies every service in the inventory.
func Evaluate(inv *model.Inventory, rev *revoke.Revoker, t time.Time, windowDays int) ([]ServiceResult, error) {
	window := time.Duration(windowDays) * 24 * time.Hour
	results := make([]ServiceResult, 0, len(inv.Services))

	for _, svc := range inv.Services {
		// Evaluate every relevant leaf up front so the revocation service is
		// queried for exactly the issuers on the anchored chains of the bound
		// leaf and of every leaf covering this service's identity.
		evals := map[string]*leafEval{}
		evalLeaf := func(leaf *model.Certificate) (*leafEval, error) {
			if e, ok := evals[leaf.ID]; ok {
				return e, nil
			}
			ch, anchored := chain.Build(inv, leaf)
			e := &leafEval{chain: ch, anchored: anchored}
			if anchored {
				e.structOK = chain.ValidateStructure(inv, ch, svc.ServerName, t)
				revoked, err := rev.ChainRevoked(ch, t)
				if err != nil {
					return nil, err
				}
				e.revoked = revoked
			}
			evals[leaf.ID] = e
			return e, nil
		}

		bound := inv.ByID(svc.BoundID)
		if bound != nil && !bound.IsCA {
			if _, err := evalLeaf(bound); err != nil {
				return nil, err
			}
		}
		var candidates []*model.Certificate
		for _, cert := range inv.Certificates {
			if cert.IsCA || !chain.ServerIdentityOK(cert, svc.ServerName) {
				continue
			}
			e, err := evalLeaf(cert)
			if err != nil {
				return nil, err
			}
			usable := e.anchored && e.structOK && !e.revoked
			fresh := cert.NotAfterT().Sub(t) >= window
			if usable && fresh {
				candidates = append(candidates, cert)
			}
		}

		res := ServiceResult{
			Unit:       svc.Unit,
			ServerName: svc.ServerName,
			Enabled:    svc.Enabled,
			BoundID:    svc.BoundID,
		}

		status := classifyBound(svc, bound, evals, t, window, &res)

		best := bestReplacement(candidates)
		switch {
		case status == "compliant":
			res.Decision = "ok"
			res.Reason = "compliant"
		case best != nil:
			res.Decision = "rotate"
			res.Reason = status
			res.ReplacementFingerprint = strptr(best.Fingerprint())
		default:
			res.Decision = "block"
			res.Reason = status
		}
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Unit < results[j].Unit })
	return results, nil
}

// classifyBound returns the bound certificate's status and fills the bound-related
// report fields on res.
func classifyBound(svc *model.Service, bound *model.Certificate, evals map[string]*leafEval, t time.Time, window time.Duration, res *ServiceResult) string {
	if bound == nil || bound.IsCA {
		res.Chain = []string{}
		return "missing"
	}
	res.BoundFingerprint = strptr(bound.Fingerprint())
	res.BoundNotAfter = strptr(bound.NotAfter)
	e := evals[bound.ID]
	res.Anchored = e.anchored
	if e.anchored {
		res.Chain = fingerprints(e.chain)
	} else {
		res.Chain = []string{}
	}

	if t.Before(bound.NotBeforeT()) || t.After(bound.NotAfterT()) {
		return "expired"
	}
	if !(e.anchored && e.structOK) {
		return "untrusted"
	}
	if e.revoked {
		return "revoked"
	}
	if bound.NotAfterT().Sub(t) < window {
		return "expiring"
	}
	return "compliant"
}

// bestReplacement picks the candidate with the latest not_after, then the largest
// serial by value, then the largest fp-hex.
func bestReplacement(candidates []*model.Certificate) *model.Certificate {
	var best *model.Certificate
	for _, c := range candidates {
		if best == nil || betterThan(c, best) {
			best = c
		}
	}
	return best
}

func betterThan(a, b *model.Certificate) bool {
	if !a.NotAfterT().Equal(b.NotAfterT()) {
		return a.NotAfterT().After(b.NotAfterT())
	}
	av, _ := model.SerialValue(a.Serial)
	bv, _ := model.SerialValue(b.Serial)
	if cmp := av.Cmp(bv); cmp != 0 {
		return cmp > 0
	}
	return a.FPHex() > b.FPHex()
}
EOF_decide

cat > internal/report/report.go <<'EOF_report'
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
			if err := writeFile(outDir, "nginx/snippets/"+r.Unit+".conf", snippet); err != nil {
				return err
			}
			rotations = append(rotations, map[string]any{"unit": r.Unit, "fingerprint": *r.ReplacementFingerprint})
		case "block":
			if err := writeFile(outDir, "systemd/system/"+r.Unit+".d/override.conf", systemdOverride); err != nil {
				return err
			}
			blocked = append(blocked, r.Unit)
		}
	}

	report := map[string]any{
		"generated_by":  "certguard",
		"report_version": "1",
		"evaluated_at":  evaluatedAt,
		"services":      services,
		"rotations":     rotations,
		"blocked_units": blocked,
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
EOF_report

# Recompile so /app/bin/certguard reflects the repaired sources.
go build -o bin/certguard ./cmd/certguard

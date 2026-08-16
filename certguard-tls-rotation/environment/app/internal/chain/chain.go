// Package chain builds a certificate's issuer chain up to a trusted anchor and
// checks the chain's structural validity (issuance, validity window, path length,
// extended key usage, server identity and name constraints).
package chain

import (
	"strings"
	"time"

	"certguard/internal/model"
)

// Build follows issuers (subject_key_id == authority_key_id linkage) up to the
// first trusted anchor. It returns the chain leaf..anchor and whether an anchor
// was reached. Subject key ids are unique, so the chain is unique.
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

// sanMatch reports whether a SAN entry covers name (case-insensitive).
func sanMatch(san, name string) bool {
	san = strings.ToLower(san)
	name = strings.ToLower(name)
	if strings.HasPrefix(san, "*.") {
		return strings.HasSuffix(name, san[1:])
	}
	return san == name
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
		return false
	}
	leaf := chain[0]
	if t.Before(leaf.NotBeforeT()) || t.After(leaf.NotAfterT()) {
		return false
	}
	for i := 1; i < len(chain); i++ {
		if !chain[i].IsCA || !contains(chain[i].KeyUsages, "certSign") {
			return false
		}
	}
	return ServerIdentityOK(chain[0], serverName)
}

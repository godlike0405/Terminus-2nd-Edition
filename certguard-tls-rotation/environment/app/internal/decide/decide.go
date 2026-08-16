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

// bestReplacement selects a replacement certificate from the candidates.
func bestReplacement(candidates []*model.Certificate) *model.Certificate {
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

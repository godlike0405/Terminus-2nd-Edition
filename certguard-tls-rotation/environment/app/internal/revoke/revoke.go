// Package revoke consults the revocation service and reports whether a
// certificate is revoked as of the evaluation instant.
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

// CertRevoked reports whether cert is listed on its issuer's CRL as of t.
func (r *Revoker) CertRevoked(cert *model.Certificate, t time.Time) (bool, error) {
	crl, err := r.crlFor(cert.AuthorityKeyID)
	if err != nil {
		return false, err
	}
	if crl == nil {
		return false, nil
	}
	for _, entry := range crl.Entries {
		if entry.Serial == cert.Serial {
			return true, nil
		}
	}
	return false, nil
}

// ChainRevoked reports whether any non-anchor certificate on chain is revoked.
func (r *Revoker) ChainRevoked(chain []*model.Certificate, t time.Time) (bool, error) {
	for i := 0; i < len(chain)-1; i++ {
		revoked, err := r.CertRevoked(chain[i], t)
		if err != nil {
			return false, err
		}
		if revoked {
			return true, nil
		}
	}
	return false, nil
}

// Package model holds the certguard inventory types and the helpers that load an
// inventory, normalize serials, parse times and compute certificate fingerprints.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"certguard/internal/canon"
)

// NameConstraints holds a CA's permitted/excluded dNSName subtrees.
type NameConstraints struct {
	Permitted []string `json:"permitted"`
	Excluded  []string `json:"excluded"`
}

// Certificate is one entry of certificates.json.
type Certificate struct {
	ID              string           `json:"id"`
	Subject         string           `json:"subject"`
	SubjectKeyID    string           `json:"subject_key_id"`
	AuthorityKeyID  string           `json:"authority_key_id"`
	Serial          string           `json:"serial"`
	NotBefore       string           `json:"not_before"`
	NotAfter        string           `json:"not_after"`
	IsCA            bool             `json:"is_ca"`
	PathLen         *int             `json:"path_len"`
	KeyUsages       []string         `json:"key_usages"`
	ExtKeyUsages    []string         `json:"ext_key_usages"`
	SANs            []string         `json:"sans"`
	NameConstraints *NameConstraints `json:"name_constraints"`

	normSerial string
	notBefore  time.Time
	notAfter   time.Time
}

// Service is one entry of services.json.
type Service struct {
	Unit       string `json:"unit"`
	ServerName string `json:"server_name"`
	BoundID    string `json:"bound_id"`
	Enabled    bool   `json:"enabled"`
}

// Policy is policy.json.
type Policy struct {
	EvaluatedAt        string `json:"evaluated_at"`
	RotationWindowDays int    `json:"rotation_window_days"`
}

// Inventory is the loaded host TLS inventory.
type Inventory struct {
	Certificates []*Certificate
	Services     []*Service
	TrustStore   map[string]bool // subject_key_id -> trusted anchor
	Policy       Policy

	byID  map[string]*Certificate
	bySKI map[string]*Certificate
}

// NormalizeSerial parses a decimal or 0x-hex serial and renders it as lowercase
// hex with no prefix and no leading zeros.
func NormalizeSerial(s string) (string, error) {
	s = strings.TrimSpace(s)
	n := new(big.Int)
	var ok bool
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, ok = n.SetString(s[2:], 16)
	} else {
		_, ok = n.SetString(s, 10)
	}
	if !ok || n.Sign() < 0 {
		return "", fmt.Errorf("invalid serial %q", s)
	}
	return strings.ToLower(n.Text(16)), nil
}

// SerialValue parses a serial into its integer value for comparison.
func SerialValue(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	n := new(big.Int)
	var ok bool
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, ok = n.SetString(s[2:], 16)
	} else {
		_, ok = n.SetString(s, 10)
	}
	if !ok {
		return nil, fmt.Errorf("invalid serial %q", s)
	}
	return n, nil
}

// ParseTime parses an RFC 3339 timestamp.
func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// NormSerial returns the certificate's normalized serial.
func (c *Certificate) NormSerial() string { return c.normSerial }

// NotBeforeT / NotAfterT return the parsed validity bounds.
func (c *Certificate) NotBeforeT() time.Time { return c.notBefore }
func (c *Certificate) NotAfterT() time.Time  { return c.notAfter }

// fingerprintObject builds the exact map hashed for the fingerprint.
func (c *Certificate) fingerprintObject() map[string]any {
	strs := func(in []string) []any {
		out := make([]any, 0, len(in))
		for _, s := range in {
			out = append(out, s)
		}
		return out
	}
	var nc any
	if c.NameConstraints != nil {
		nc = map[string]any{
			"permitted": strs(c.NameConstraints.Permitted),
			"excluded":  strs(c.NameConstraints.Excluded),
		}
	} else {
		nc = nil
	}
	var pathLen any
	if c.PathLen != nil {
		pathLen = *c.PathLen
	} else {
		pathLen = nil
	}
	return map[string]any{
		"aki":              c.AuthorityKeyID,
		"eku":              strs(c.ExtKeyUsages),
		"is_ca":            c.IsCA,
		"ku":               strs(c.KeyUsages),
		"name_constraints": nc,
		"not_after":        c.NotAfter,
		"not_before":       c.NotBefore,
		"path_len":         pathLen,
		"sans":             strs(c.SANs),
		"serial":           c.normSerial,
		"ski":              c.SubjectKeyID,
		"subject":          c.Subject,
	}
}

// FPHex returns the 64-hex-character fingerprint (no "sha256:" prefix).
func (c *Certificate) FPHex() string {
	sum := sha256.Sum256(canon.Compact(c.fingerprintObject()))
	return hex.EncodeToString(sum[:])
}

// Fingerprint returns the full "sha256:<hex>" fingerprint.
func (c *Certificate) Fingerprint() string { return "sha256:" + c.FPHex() }

// LoadInventory reads the four inventory documents from dir.
func LoadInventory(dir string) (*Inventory, error) {
	inv := &Inventory{
		TrustStore: map[string]bool{},
		byID:       map[string]*Certificate{},
		bySKI:      map[string]*Certificate{},
	}

	if err := readJSON(filepath.Join(dir, "certificates.json"), &inv.Certificates); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, "services.json"), &inv.Services); err != nil {
		return nil, err
	}
	var anchors []string
	if err := readJSON(filepath.Join(dir, "trust-store.json"), &anchors); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, "policy.json"), &inv.Policy); err != nil {
		return nil, err
	}
	for _, a := range anchors {
		inv.TrustStore[a] = true
	}
	for _, c := range inv.Certificates {
		ns, err := NormalizeSerial(c.Serial)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: %w", c.ID, err)
		}
		c.normSerial = ns
		if c.notBefore, err = ParseTime(c.NotBefore); err != nil {
			return nil, fmt.Errorf("certificate %s not_before: %w", c.ID, err)
		}
		if c.notAfter, err = ParseTime(c.NotAfter); err != nil {
			return nil, fmt.Errorf("certificate %s not_after: %w", c.ID, err)
		}
		inv.byID[c.ID] = c
		inv.bySKI[c.SubjectKeyID] = c
	}
	return inv, nil
}

// ByID returns the certificate with the given id, or nil.
func (inv *Inventory) ByID(id string) *Certificate { return inv.byID[id] }

// BySKI returns the certificate whose subject_key_id equals ski, or nil.
func (inv *Inventory) BySKI(ski string) *Certificate { return inv.bySKI[ski] }

// IsAnchor reports whether ski is a trusted anchor.
func (inv *Inventory) IsAnchor(ski string) bool { return inv.TrustStore[ski] }

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

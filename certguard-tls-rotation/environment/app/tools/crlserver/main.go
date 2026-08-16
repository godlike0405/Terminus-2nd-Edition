// Command crlserver is a local mirror of the revocation service. It serves the
// same POST /v1/revocations contract from the CRL JSON files under a directory,
// so certguard can be exercised offline against the shipped inventory.
//
// Usage: go run ./tools/crlserver [port] [crl-dir]
//
//	port default 8730, crl-dir default /app/vendor-crl. A file <issuer_key_id>.json
//	in crl-dir holds that issuer's CRL object; a missing file yields {"crl": null}.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	port := "8730"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	dir := "/app/vendor-crl"
	if len(os.Args) > 2 {
		dir = os.Args[2]
	}

	http.HandleFunc("/v1/revocations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		var req struct {
			IssuerKeyID string `json:"issuer_key_id"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.IssuerKeyID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var crl json.RawMessage = []byte("null")
		if data, err := os.ReadFile(filepath.Join(dir, req.IssuerKeyID+".json")); err == nil {
			crl = data
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"crl":`))
		w.Write(crl)
		w.Write([]byte(`}`))
	})

	addr := "127.0.0.1:" + port
	fmt.Printf("crl mirror listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "crlserver:", err)
		os.Exit(1)
	}
}

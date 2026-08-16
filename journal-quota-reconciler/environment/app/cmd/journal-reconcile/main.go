package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type Inventory struct {
	Filesystems []map[string]any `json:"filesystems"`
	Namespaces  []map[string]any `json:"namespaces"`
}

func main() {
	invPath := flag.String("inventory", "", "inventory JSON")
	polPath := flag.String("policy", "", "policy JSON")
	out := flag.String("output", "", "output directory")
	flag.Parse()
	if *invPath == "" || *polPath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "missing flags")
		os.Exit(2)
	}
	var inv Inventory
	b, err := os.ReadFile(*invPath)
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &inv); err != nil {
		panic(err)
	}
	// This provisional implementation ignores policy coupling between namespaces.
	if err = os.MkdirAll(filepath.Join(*out, "journald"), 0755); err != nil {
		panic(err)
	}
	for _, n := range inv.Namespaces {
		name := fmt.Sprint(n["name"])
		body := fmt.Sprintf("[Journal]\nSystemMaxUse=%v\nSystemKeepFree=0\n", n["usage_bytes"])
		_ = os.WriteFile(filepath.Join(*out, "journald", name+".conf"), []byte(body), 0644)
	}
	_ = os.WriteFile(filepath.Join(*out, "plan.json"), []byte("{\"filesystems\":[],\"vacuum\":[]}\n"), 0644)
}

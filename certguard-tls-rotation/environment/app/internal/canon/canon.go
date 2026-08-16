// Package canon renders canonical JSON: recursively key-sorted (Go's encoding/json
// sorts map keys), compact separators, no HTML escaping, so the byte layout is
// stable and reproducible. Build values as map[string]any / []any so every object
// is emitted with sorted keys.
package canon

import (
	"bytes"
	"encoding/json"
)

// Compact returns the canonical JSON of v with no trailing newline.
func Compact(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b
}

// WithNewline returns the canonical JSON of v followed by exactly one newline.
func WithNewline(v any) []byte {
	return append(Compact(v), '\n')
}

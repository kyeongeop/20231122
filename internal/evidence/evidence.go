// Package evidence preserves key forensic artifacts: stable hashes, bounded
// snippets for the audit log, and full payloads on disk.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Hash returns the hex SHA-256 of b.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Snippet returns a bounded, escaped, single-line preview of b safe for logs.
func Snippet(b []byte, max int) string {
	if len(b) > max {
		return strconv.Quote(string(b[:max])) + fmt.Sprintf("...(%d bytes total)", len(b))
	}
	return strconv.Quote(string(b))
}

// SaveFile writes payload under dir with a hash-derived name and returns the
// path. Used to preserve full smuggled requests and oversized inputs.
func SaveFile(dir, prefix string, payload []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.bin", sanitize(prefix), Hash(payload)[:16])
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

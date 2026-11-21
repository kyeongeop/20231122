package model

import (
	"fmt"
	"path"
	"strings"
)

const maxPathBytes = 256

// CanonicalPath makes equivalent slash forms comparable while keeping the
// path case-sensitive. The experimental question is alias normalization, not
// filesystem case folding.
func CanonicalPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("path is empty")
	}
	if len(value) > maxPathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", maxPathBytes)
	}
	if strings.ContainsAny(value, "?#") {
		return "", fmt.Errorf("path must not contain query or fragment markers")
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("path must be absolute")
	}

	cleaned := path.Clean(value)
	if cleaned == "." {
		cleaned = "/"
	}
	return cleaned, nil
}

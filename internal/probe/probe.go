// Package probe is the deterministic Go side of the libFuzzer corpus target.
// It reduces an input to stable features that can be compared across runs.
package probe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"corpusd/internal/model"
)

const Format = "libfuzzer-corpus/v1"

func Analyze(data []byte, inputSHA, mode string) model.Analysis {
	contentSHA := inputSHA
	if contentSHA == "" {
		sum := sha256.Sum256(data)
		contentSHA = hex.EncodeToString(sum[:])
	}
	if mode == model.ModeDegraded {
		return model.Analysis{
			Format:        Format,
			ContentSHA256: contentSHA,
			ResultSHA256:  digest("degraded", contentSHA, len(data)),
		}
	}

	var seen [256]bool
	features := 0
	edges := uint64(1469598103934665603)
	for _, b := range data {
		if !seen[b] {
			seen[b] = true
			features++
		}
		edges ^= uint64(b)
		edges *= 1099511628211
	}
	result := digest("full", contentSHA, len(data), fmt.Sprintf("%016x", edges))
	return model.Analysis{
		Format:        Format,
		Features:      features,
		CoverageBytes: len(data),
		ContentSHA256: contentSHA,
		ResultSHA256:  result,
	}
}

func digest(parts ...any) string {
	h := sha256.New()
	for _, part := range parts {
		switch v := part.(type) {
		case string:
			h.Write([]byte(v))
			h.Write([]byte{0})
		case int:
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(v))
			h.Write(buf[:])
		default:
			fmt.Fprint(h, v)
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

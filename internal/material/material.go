// Package material builds and preserves the original material: a
// deterministic byte blob with extreme content that record values are
// sliced from at recorded raw offsets.
package material

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

// Size of the generated original material.
const Size = 1 << 20 // 1 MiB

// Generate deterministically builds the original material from seed.
// It deliberately contains HTML-special characters, template markers,
// invalid UTF-8 and long runs so the escaping engine is stressed.
func Generate(seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, 0, Size)
	chunks := [][]byte{
		[]byte(`<div class="user">{{name}}&"'"</div>`),
		[]byte("{{unterminated"),
		[]byte("}}}}{{"),
		{0xff, 0xfe, 0x00, 0x80, '<', '>', '&'},
		[]byte("SELECT * FROM t WHERE x='{{q}}';"),
	}
	for len(buf) < Size {
		switch rng.Intn(8) {
		case 0:
			buf = append(buf, chunks[rng.Intn(len(chunks))]...)
		case 1:
			buf = append(buf, []byte(fmt.Sprintf("record-%d ", rng.Intn(100000)))...)
		case 2:
			for i := 0; i < 64+rng.Intn(512); i++ {
				buf = append(buf, "&#<>\""[rng.Intn(5)])
			}
		default:
			buf = append(buf, byte(rng.Intn(256)))
		}
	}
	return buf[:Size]
}

// SHA256 returns the hex-encoded SHA-256 of b.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Preserve writes the material read-only next to its .sha256 sidecar.
// An existing file is never modified; a hash mismatch is an error.
func Preserve(dir string, data []byte) (string, error) {
	path := filepath.Join(dir, "material.bin")
	sum := SHA256(data)
	if existing, err := os.ReadFile(path); err == nil {
		if SHA256(existing) != sum {
			return "", fmt.Errorf("original material at %s was modified: have %s want %s",
				path, SHA256(existing), sum)
		}
		return sum, nil // already preserved, untouched
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o444); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".sha256", []byte(sum+"\n"), 0o444); err != nil {
		return "", err
	}
	return sum, nil
}

// VerifyPreserved re-reads the preserved copy and checks it against sum.
func VerifyPreserved(dir, sum string) error {
	data, err := os.ReadFile(filepath.Join(dir, "material.bin"))
	if err != nil {
		return err
	}
	if got := SHA256(data); got != sum {
		return fmt.Errorf("preserved material hash mismatch: have %s want %s", got, sum)
	}
	return nil
}

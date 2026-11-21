package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/example/jwtconf/internal/evidence"
	"github.com/example/jwtconf/internal/jwt"
	"github.com/example/jwtconf/internal/pipeline"
)

func main() {
	outDir := flag.String("out", "artifacts/evidence", "directory for the SQLite evidence DB")
	flag.Parse()
	if err := run(*outDir); err != nil {
		log.Fatalf("run failed: %v", err)
	}
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	dbPath := filepath.Join(outDir, "evidence.db")
	store, err := evidence.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	objects, err := buildObjects(key)
	if err != nil {
		return err
	}

	res, err := pipeline.Run(objects, store, outDir, &key.PublicKey)
	if err != nil {
		return err
	}
	pipeline.LogSummary(res)

	fmt.Printf("evidence db: %s\n", dbPath)
	fmt.Printf("records: %d, object errors (continued): %d\n", len(res.Records), len(res.Errors))
	fmt.Printf("temp dir %s cleaned: %v\n", res.TmpDir, res.Cleaned)

	// Re-read through the compatibility layer to prove both formats decode.
	all, err := store.List()
	if err != nil {
		return err
	}
	for _, r := range all {
		fmt.Printf("review %s fmt=v%d object=%s decision=%s trigger=%s snaps=%d logs=%d\n",
			r.ID, r.Format, r.Object, r.Decision, r.Trigger, len(r.Snaps), len(r.Logs))
	}
	return nil
}

// buildObjects creates the attack set: a legitimate token, the alg-confusion
// forgery, a none-alg probe, a malformed input (exercises continue-on-error),
// and a legacy-format replay.
func buildObjects(key *rsa.PrivateKey) ([]pipeline.Object, error) {
	admin := map[string]any{"sub": "attacker", "role": "admin"}

	legit, err := jwt.SignRS256(map[string]any{"sub": "user", "role": "reader"}, key, nil)
	if err != nil {
		return nil, err
	}
	// Forgery: HS256 signed with the public key as HMAC secret.
	forged, err := jwt.SignHS256(admin, jwt.PublicKeyDER(&key.PublicKey), nil)
	if err != nil {
		return nil, err
	}
	noneAlg := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
	malformed := "not-a-jwt"

	return []pipeline.Object{
		{Name: "legit-rs256", Token: legit},
		{Name: "forge-hs256-confusion", Token: forged},
		{Name: "probe-none-alg", Token: noneAlg},
		{Name: "malformed-input", Token: malformed},
		{Name: "replay-legacy", Token: forged},
	}, nil
}

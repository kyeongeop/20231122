package pipeline

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/jwtconf/internal/evidence"
	"github.com/example/jwtconf/internal/jwt"
)

func TestRunContinuesAfterErrorAndCleansUp(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	legit, err := jwt.SignRS256(map[string]any{"sub": "u"}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jwt.SignHS256(map[string]any{"role": "admin"},
		jwt.PublicKeyDER(&key.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	store, err := evidence.Open(filepath.Join(dir, "ev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	objects := []Object{
		{Name: "ok", Token: legit},
		{Name: "bad", Token: "garbage"},
		{Name: "forge", Token: forged},
	}
	res, err := Run(objects, store, dir, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 {
		t.Fatalf("want 3 records despite bad input, got %d", len(res.Records))
	}
	if !res.Cleaned {
		t.Fatal("temp state not cleaned")
	}
	if _, err := os.Stat(res.TmpDir); !os.IsNotExist(err) {
		t.Fatalf("temp dir still exists: %s", res.TmpDir)
	}

	var sawConfusion bool
	for _, r := range res.Records {
		if r.Object == "forge" && r.Decision == "deny" &&
			r.Reason == "alg-confusion accepted by legacy, rejected by fixed" {
			sawConfusion = true
		}
		if r.Trigger == "" || r.AttackHash == "" || len(r.Logs) == 0 {
			t.Fatalf("record %s missing correlated evidence: %+v", r.ID, r)
		}
	}
	if !sawConfusion {
		t.Fatal("alg confusion not reproduced")
	}
}

package material

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"krfix/internal/store"
)

func TestSealVerifyAndImport(t *testing.T) {
	ctx := context.Background()
	layout := NewLayout(t.TempDir())
	if err := os.MkdirAll(layout.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(layout.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw, anchors, err := SealOriginal(ctx, layout, db)
	if err != nil {
		t.Fatalf("SealOriginal: %v", err)
	}
	if len(anchors) != 3 {
		t.Fatalf("anchors=%d want 3", len(anchors))
	}

	// Read-only bit is enforced.
	info, _ := os.Stat(filepath.Join(layout.OriginalDir, originalName))
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("original mode=%o want 0444", info.Mode().Perm())
	}

	// Re-seal must be refused; original stays untouched.
	if _, _, err := SealOriginal(ctx, layout, db); err == nil {
		t.Fatal("expected re-seal to be refused")
	}
	if err := VerifyOriginal(ctx, layout, db); err != nil {
		t.Fatalf("VerifyOriginal after seal: %v", err)
	}

	// Tamper detection on the pinned hash.
	path := filepath.Join(layout.OriginalDir, originalName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[0] ^= 0xFF
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOriginal(ctx, layout, db); err == nil {
		t.Fatal("expected tamper detection")
	}

	// Import an attack sample and check raw offsets are persisted.
	seeds := CorpusSeeds()
	var attack Seed
	for _, s := range seeds {
		if s.Kind == "attack" {
			attack = s
			break
		}
	}
	sample, err := ImportSample(ctx, layout, db, attack.Name, attack.Kind, attack.Build())
	if err != nil {
		t.Fatalf("ImportSample: %v", err)
	}
	if sample.AnchorOffsets != [3]int64{0, 16, 64} {
		t.Fatalf("sample offsets=%v", sample.AnchorOffsets)
	}
	if sample.ClientEpoch >= sample.AttestEpoch {
		t.Fatalf("attack seed should be stale: %+v", sample)
	}
}

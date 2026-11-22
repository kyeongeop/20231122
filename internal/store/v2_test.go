package store

import (
	"errors"
	"path/filepath"
	"testing"

	"quotabypass/internal/evidence"
	"quotabypass/internal/quota"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	st, err := OpenV2(filepath.Join(t.TempDir(), "evidence.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	specs := quota.DefaultScenarios()
	for i, sc := range specs {
		rec := quota.NewRunner(sc.Mode).Run(sc.Name, i, sc.Raw)
		if err := st.Save(rec); err != nil {
			t.Fatalf("save %s: %v", sc.Name, err)
		}
	}

	ordinals, err := st.Ordinals()
	if err != nil || len(ordinals) != len(specs) {
		t.Fatalf("ordinals: %v %v", ordinals, err)
	}

	for i := range specs {
		got, err := st.Load(i)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if err := evidence.VerifyRecord(got); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		if len(got.Attempts) != got.AttackInput.ConcurrentRequests {
			t.Fatalf("attempt count drift at %d", i)
		}
	}

	if _, err := st.Load(99); !errors.Is(err, ErrNotFoundV2) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestSaveRejectsTamperedRecord(t *testing.T) {
	st, err := OpenV2(filepath.Join(t.TempDir(), "evidence.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	spec := quota.DefaultScenarios()[0]
	rec := quota.NewRunner(spec.Mode).Run(spec.Name, 0, spec.Raw)
	if err := st.Save(rec); err != nil {
		t.Fatal(err)
	}

	if _, err := st.db.Exec(
		`UPDATE records SET summary = REPLACE(summary, '"allowed":4', '"allowed":40')
		 WHERE ordinal = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(0); err == nil {
		t.Fatal("tampered record must fail hash verification on reload")
	}
}

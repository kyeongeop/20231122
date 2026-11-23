package experiment

import (
	"context"
	"path/filepath"
	"testing"

	"example.com/deserialize-boundary/internal/ledger"
)

func TestCoreExperimentAndReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source, err := ledger.Open(filepath.Join(dir, "experiment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	results, err := (&Runner{Ledger: source, OutDir: dir}).RunCore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(CoreScenarios()) {
		t.Fatalf("got %d runs, want %d", len(results), len(CoreScenarios()))
	}
	checks, err := (&Checker{Ledger: source}).EvaluateCore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if !check.Passed {
			t.Errorf("check %s failed: expected=%s observed=%s", check.ID, check.Expected, check.Observed)
		}
	}
	cancelRows, err := source.Records(ctx, "cancel-target")
	if err != nil {
		t.Fatal(err)
	}
	if len(cancelRows) != 0 {
		t.Fatalf("cancel-target committed %d rows", len(cancelRows))
	}

	destination, err := ledger.Open(filepath.Join(dir, "replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	replays, err := ReplayCore(ctx, source, destination, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, replay := range replays {
		if !replay.StatusEqual || !replay.DigestEqual || !replay.StepsEqual || !replay.HashesEqual {
			t.Errorf("replay mismatch: %+v", replay)
		}
	}
}

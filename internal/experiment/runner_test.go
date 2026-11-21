package experiment

import (
	"path/filepath"
	"testing"

	"pathaliaslab/internal/ledger"
)

func TestExecuteAllAndReplay(t *testing.T) {
	store, err := ledger.Open(filepath.Join(t.TempDir(), "experiment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runs, global, err := ExecuteAll(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 5 {
		t.Fatalf("runs=%d", len(runs))
	}
	for _, run := range runs {
		if !run.Passed {
			t.Fatalf("run %s failed", run.RunID)
		}
		if err := store.VerifyEvidenceChain(run.RunID); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range global {
		if !check.Passed {
			t.Fatalf("global check %s failed: expected=%s actual=%s",
				check.CheckName, check.Expected, check.Actual)
		}
	}
	replays, err := store.Replays()
	if err != nil {
		t.Fatal(err)
	}
	if len(replays) != 1 || !replays[0].Passed {
		t.Fatalf("replays=%+v", replays)
	}
}

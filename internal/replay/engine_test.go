package replay

import (
	"path/filepath"
	"testing"

	"timeoutfsm/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRecoveryReplayMatchesJournal(t *testing.T) {
	st := openStore(t)
	res, err := Execute(st, "run-baseline", BaselineRecovery(), true)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Replayed || !res.ReplayMatch {
		t.Fatalf("replay must match, got match=%v mismatches=%d",
			res.ReplayMatch, res.ReplayMismatch)
	}

	rows, err := st.Events("run-baseline")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(BaselineRecovery().Events) {
		t.Fatalf("journaled %d rows, want %d", len(rows), len(BaselineRecovery().Events))
	}
	n, err := st.ReplayMismatchCount("run-baseline")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("persisted mismatches = %d, want 0", n)
	}
}

func TestUnknownExtensionRejectedButFlowContinues(t *testing.T) {
	st := openStore(t)
	res, err := Execute(st, "run-ext", UnknownExtensionControl(), true)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var unknown, rejected int
	var finalState string
	for _, step := range res.Steps {
		if step.Input.Kind == "X_PING" {
			unknown++
			if step.Outcome.Accepted {
				t.Fatal("unknown extension must be rejected")
			}
		}
		if !step.Outcome.Accepted {
			rejected++
		}
		finalState = string(step.Snapshot.State)
	}
	if unknown != 1 || rejected != 1 {
		t.Fatalf("unknown=%d rejected=%d, want 1/1", unknown, rejected)
	}
	if finalState != "CLOSED" {
		t.Fatalf("final state = %s, want CLOSED", finalState)
	}
	if !res.ReplayMatch {
		t.Fatal("control scenario replay must match")
	}
}

func TestReorderAndDuplicateScenarios(t *testing.T) {
	st := openStore(t)

	reorder, err := Execute(st, "run-reorder", ReorderCheck(), false)
	if err != nil {
		t.Fatal(err)
	}
	var staleRejects int
	for _, step := range reorder.Steps {
		if !step.Outcome.Accepted && step.Input.Kind == "TIMEOUT" {
			staleRejects++
		}
	}
	if staleRejects == 0 {
		t.Fatal("reordered TIMEOUT must be rejected at least once")
	}

	dup, err := Execute(st, "run-dup", DuplicateSubmit(), false)
	if err != nil {
		t.Fatal(err)
	}
	var duplicates int
	for _, step := range dup.Steps {
		if step.Outcome.Duplicate {
			duplicates++
		}
	}
	if duplicates != 1 {
		t.Fatalf("duplicates = %d, want 1", duplicates)
	}
}

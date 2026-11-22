package store

import (
	"path/filepath"
	"testing"
)

func TestRunAndSampleRoundtrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	run := &Run{Name: "t", Status: "running", Mode: "fuzz",
		MaxRuns: 10, MaxLen: 256, Seed: 1, Jobs: 1}
	runID, err := st.CreateRun(run)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	smp := Sample{RunID: runID, SampleKey: "attack/x", Scenario: "missing-fragment-attack",
		Input: "sid=v; Secure"}
	if err := st.AddSample(&smp); err != nil {
		t.Fatalf("add sample: %v", err)
	}
	if err := st.SetSampleStatus(smp.ID, "running"); err != nil {
		t.Fatalf("mark running: %v", err)
	}

	if n, err := st.RequeueRunning(runID); err != nil || n != 1 {
		t.Fatalf("requeue: n=%d err=%v", n, err)
	}
	pending, err := st.PendingSamples(runID)
	if err != nil || len(pending) != 1 || pending[0].Status != "pending" {
		t.Fatalf("pending after requeue: %+v err=%v", pending, err)
	}

	if err := st.AddFindings(smp.ID, []Finding{
		{Severity: "CRIT", Code: "MISSING_SECURE", Message: "no secure"},
	}); err != nil {
		t.Fatalf("findings: %v", err)
	}
	got, err := st.Findings(smp.ID)
	if err != nil || len(got) != 1 || got[0].Code != "MISSING_SECURE" {
		t.Fatalf("findings roundtrip: %+v err=%v", got, err)
	}

	runs, err := st.ListRuns()
	if err != nil || len(runs) != 1 || runs[0].Total != 1 || runs[0].Pending != 1 {
		t.Fatalf("list runs: %+v err=%v", runs, err)
	}
}

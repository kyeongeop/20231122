package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestJobLifecycleAndRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	sample := Sample{
		Name: "atk_x", Kind: "attack", RawPath: "/tmp/x", SHA256: "abc",
		Size: 108, AnchorOffsets: [3]int64{0, 16, 64},
		ClientEpoch: 4, ServerEpoch: 5, AttestEpoch: 5,
	}
	sid, err := InsertSample(ctx, db, sample)
	if err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	jobID, err := EnsureJob(ctx, db, sid, "vuln")
	if err != nil {
		t.Fatalf("EnsureJob: %v", err)
	}

	job, err := ClaimJob(ctx, db, "atk_x", "vuln")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if job.State != "running" || job.Attempts != 1 {
		t.Fatalf("unexpected claimed job: %+v", job)
	}

	// A second claim while running must find nothing pending.
	if _, err := ClaimJob(ctx, db, "atk_x", "vuln"); err == nil {
		t.Fatal("expected no claimable running job")
	}

	// Simulate a crash mid-run, then re-enter: running -> interrupted.
	n, err := ResetRunningOnStartup(ctx, db)
	if err != nil || n != 1 {
		t.Fatalf("ResetRunningOnStartup n=%d err=%v", n, err)
	}
	job2, err := ClaimJob(ctx, db, "atk_x", "vuln")
	if err != nil {
		t.Fatalf("reclaim after recovery: %v", err)
	}
	if job2.Attempts != 2 {
		t.Fatalf("attempts after recovery=%d want 2", job2.Attempts)
	}

	runID, err := InsertRun(ctx, db, jobID, 2)
	if err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := FinishRun(ctx, db, runID, 77, 12345,
		LabelForTest()); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	if err := FinishJob(ctx, db, jobID, "done"); err != nil {
		t.Fatalf("FinishJob: %v", err)
	}
	state, err := JobState(ctx, db, "atk_x", "vuln")
	if err != nil || state != "done" {
		t.Fatalf("final state=%q err=%v", state, err)
	}

	// Redo path: done -> pending, historical run retained.
	if err := ReopenJob(ctx, db, sid, "vuln"); err != nil {
		t.Fatalf("ReopenJob: %v", err)
	}
	state, _ = JobState(ctx, db, "atk_x", "vuln")
	if state != "pending" {
		t.Fatalf("after reopen state=%q want pending", state)
	}
	var runCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM runs`).Scan(&runCount); err != nil || runCount != 1 {
		t.Fatalf("historical runs=%d err=%v", runCount, err)
	}
}

func TestAnchorPersistence(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i, off := range []int64{0, 16, 64} {
		if err := InsertAnchor(ctx, db, i+1,
			[]string{"KRFIXH01", "KRFIXP02", "KRFIXA03"}[i],
			[]string{"header", "payload", "attestation"}[i],
			off, 16); err != nil {
			t.Fatal(err)
		}
	}
	got, err := AnchorOffsets(ctx, db)
	if err != nil || got != [3]int64{0, 16, 64} {
		t.Fatalf("offsets=%v err=%v", got, err)
	}
}

// LabelForTest keeps the test independent of the runner package labels.
func LabelForTest() string { return "ROTATION_FAILURE_REPRODUCED" }

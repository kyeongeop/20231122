package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"idorfix/internal/domain"
)

func TestRunStateMachineAndRecovery(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "workspace.db")
	workspace, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer workspace.Close()

	sample := &domain.Sample{
		SchemaVersion: domain.SchemaVersion,
		SampleID:      "DB-1",
		Title:         "db test",
		AttackClass:   "TEST",
		InputSHA256:   "deadbeef",
		CreatedAt:     time.Now().UTC(),
	}
	if err := workspace.InsertSample(ctx, sample, `{"sample_id":"DB-1"}`, 1); err != nil {
		t.Fatalf("insert sample: %v", err)
	}

	run := &domain.Run{
		RunID:       "run-DB-1-a1",
		SampleID:    "DB-1",
		Attempt:     1,
		Status:      domain.StatusPending,
		StartedAt:   time.Now().UTC(),
		PID:         1 << 20,
		InputSHA256: "deadbeef",
		RuleVersion: "test",
	}
	if err := workspace.InsertPendingRun(ctx, run, 1); err != nil {
		t.Fatalf("insert pending run: %v", err)
	}
	if err := workspace.MarkRunning(ctx, run.RunID); err != nil {
		t.Fatalf("mark running: %v", err)
	}

	recovered, err := workspace.RecoverInterrupted(ctx, func(pid int) bool { return false })
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(recovered) != 1 || recovered[0].Status != domain.StatusInterrupted {
		t.Fatalf("expected one interrupted run, got %+v", recovered)
	}

	// A live PID must never be reclaimed.
	if err := workspace.InsertPendingRun(ctx, &domain.Run{
		RunID: "run-DB-1-a2", SampleID: "DB-1", Attempt: 2,
		Status: domain.StatusPending, StartedAt: time.Now().UTC(),
		PID: os.Getpid(), InputSHA256: "deadbeef", RuleVersion: "test",
	}, 2); err != nil {
		t.Fatalf("insert second run: %v", err)
	}
	if err := workspace.MarkRunning(ctx, "run-DB-1-a2"); err != nil {
		t.Fatalf("mark second running: %v", err)
	}
	recovered, err = workspace.RecoverInterrupted(ctx, func(pid int) bool { return pid == os.Getpid() })
	if err != nil {
		t.Fatalf("recover live: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("live process must not be recovered, got %+v", recovered)
	}
}

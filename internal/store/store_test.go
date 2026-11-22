package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestSeedPreservesFullAttemptChain(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "trace.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	check, err := s.GetCheck(context.Background(), "CHK-1A7F")
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Attempts) != 4 {
		t.Fatalf("attempts = %d, want 4", len(check.Attempts))
	}
	if len(check.Evidence) != 5 || len(check.Findings) != 3 || len(check.Audits) != 7 {
		t.Fatalf("evidence=%d findings=%d audits=%d", len(check.Evidence), len(check.Findings), len(check.Audits))
	}
	cancelled := 0
	for _, attempt := range check.Attempts {
		if attempt.Status == "cancelled" {
			cancelled++
		}
	}
	if cancelled != 2 {
		t.Fatalf("cancelled attempts = %d, want 2", cancelled)
	}
}

func TestFinalizedAttemptCannotBeCancelled(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "trace.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	err = s.CancelAttempt(context.Background(), "CHK-1A7F", "CHK-1A7F-A04", "tester", "late cancel")
	if !errors.Is(err, ErrAttemptFinalized) {
		t.Fatalf("cancel finalized attempt error = %v", err)
	}
}

func TestHumanConfirmationIsAdditive(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "trace.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.ConfirmCheck(context.Background(), "CHK-1A7F", "review", "需进一步复核", "测试员", "补充证据"); err != nil {
		t.Fatal(err)
	}
	check, err := s.GetCheck(context.Background(), "CHK-1A7F")
	if err != nil {
		t.Fatal(err)
	}
	if check.HumanVerdict != "review" || check.HumanLabel != "需进一步复核" {
		t.Fatalf("human verdict = %q / %q", check.HumanVerdict, check.HumanLabel)
	}
	if check.AutoVerdict != "malicious" {
		t.Fatalf("automatic verdict was overwritten: %q", check.AutoVerdict)
	}
	if len(check.Audits) != 8 {
		t.Fatalf("audits = %d, want 8", len(check.Audits))
	}
}

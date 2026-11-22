package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStorePersistsEvidenceGraph(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	items, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("list returned %d audits, want 2", len(items))
	}

	truncated, err := store.Get(ctx, TruncatedAuditID)
	if err != nil {
		t.Fatal(err)
	}
	if truncated.FirstError == nil || truncated.FirstError.Key != "capture.complete" {
		t.Fatalf("persisted first error = %#v", truncated.FirstError)
	}
	if len(truncated.Artifacts) != 1 || truncated.Replay == nil {
		t.Fatal("truncated record lost artifact or replay relation")
	}

	replay, err := store.Get(ctx, ReplayAuditID)
	if err != nil {
		t.Fatal(err)
	}
	if replay.FirstError == nil || replay.FirstError.Key != "policy.vary" {
		t.Fatalf("persisted replay first error = %#v", replay.FirstError)
	}
	if replay.Boundary == nil || replay.Boundary.Status != StatusUndecided {
		t.Fatalf("persisted boundary = %#v", replay.Boundary)
	}
	if len(replay.Conclusions) != 4 || len(replay.Artifacts) != 2 {
		t.Fatalf("persisted replay graph incomplete: conclusions=%d artifacts=%d",
			len(replay.Conclusions), len(replay.Artifacts))
	}
	for _, conclusion := range replay.Conclusions {
		if conclusion.StepID == "" || conclusion.Evidence.ArtifactID == "" {
			t.Fatalf("conclusion %s lost its trace link: %#v", conclusion.Code, conclusion)
		}
	}
}

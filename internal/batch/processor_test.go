package batch

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"jsondepth-review/internal/evidence"
)

func openTestStore(t *testing.T) *evidence.Store {
	t.Helper()
	store, err := evidence.Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestProcessSnapshotsEndToEnd(t *testing.T) {
	store := openTestStore(t)
	proc, err := New(store, 128, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	quarantineDir := proc.QuarantineDir()

	ctx := context.Background()
	testdata := "../../testdata"
	sum1, err := proc.ProcessFile(ctx, "snapshot_v1", filepath.Join(testdata, "snapshot_v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sum2, err := proc.ProcessFile(ctx, "snapshot_v2", filepath.Join(testdata, "snapshot_v2.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	if sum1.Total != 4 || sum1.Allowed != 2 || sum1.Denied != 2 {
		t.Fatalf("v1 summary: %+v", sum1)
	}
	if sum2.Total != 3 || sum2.Allowed != 2 || sum2.Denied != 1 {
		t.Fatalf("v2 summary: %+v", sum2)
	}

	if _, err := os.Stat(filepath.Join(quarantineDir, "snapshot_v1-line2.bin")); err != nil {
		t.Fatalf("quarantine copy missing: %v", err)
	}

	entries, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("want 7 evidence rows, got %d", len(entries))
	}

	var attacks []evidence.Entry
	for _, e := range entries {
		if e.Trigger == "depth_exceeded" {
			attacks = append(attacks, e)
		}
	}
	if len(attacks) != 2 {
		t.Fatalf("want 2 depth_exceeded rows, got %d", len(attacks))
	}
	for _, a := range attacks {
		if a.Decision != "deny:unparseable" {
			t.Fatalf("attack row decision = %s", a.Decision)
		}
		if a.InputHash == "" || a.InputHead == "" || a.LogExcerpt == "" {
			t.Fatalf("attack row missing key evidence: %+v", a)
		}
		if a.Location == "" || a.Location == "-" {
			t.Fatalf("attack row missing trigger location")
		}
	}

	byID := map[string]evidence.Entry{}
	for _, e := range entries {
		if e.RecordID != "" {
			byID[e.RecordID] = e
		}
	}
	if byID["rec-001"].Format != "v1" || byID["rec-101"].Format != "v2" {
		t.Fatalf("format normalization wrong: %+v", byID)
	}
	if byID["rec-002"].Decision != "deny:policy" {
		t.Fatalf("rec-002 should be deny:policy, got %s", byID["rec-002"].Decision)
	}

	if err := proc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(quarantineDir); !os.IsNotExist(err) {
		t.Fatalf("quarantine dir should be removed, stat err=%v", err)
	}
}

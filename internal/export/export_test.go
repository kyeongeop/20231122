package export

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taintlab/internal/store"
	"taintlab/internal/taint"
)

func buildExport(t *testing.T) (string, Manifest) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "evidence.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sample, err := os.ReadFile("../../testdata/cases/unsynced-truncation.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		sample,
		nil,
		bytes.Repeat([]byte("x"), taint.MaxInputBytes+1),
		[]byte("{"),
	}
	for _, input := range cases {
		if _, err := db.SaveResult(
			ctx, taint.Execute(input), "2026-11-22T04:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := db.LoadAll(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "package")
	manifest, err := WriteDir(dir, runs, Options{ExportedAt: "2026-11-22T05:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	return dir, manifest
}

func TestExportRoundTripAndReplay(t *testing.T) {
	dir, manifest := buildExport(t)
	if manifest.RunCount != 4 || manifest.EventCount != 4 {
		t.Fatalf("manifest counts: %#v", manifest)
	}
	verification, err := VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Runs != 4 || verification.Events != 4 ||
		verification.ReplayedRuns != 3 || verification.IncompleteRuns != 1 {
		t.Fatalf("verification: %#v", verification)
	}
	records, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := `{"record_schema":"taintlab-record/v1","run_id":1,"created_at":"2026-11-22T04:00:00Z"`
	if !strings.HasPrefix(string(records), prefix) {
		t.Fatalf("record field order changed:\n%s", string(records[:min(len(records), 300)]))
	}
}

func TestExportVerifierDetectsTamper(t *testing.T) {
	dir, _ := buildExport(t)
	path := filepath.Join(dir, "records.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"status":"accepted"`),
		[]byte(`"status":"tampered"`), 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err == nil {
		t.Fatal("tampered records package was accepted")
	}
}

func TestExportVerifierDetectsReorderedRecord(t *testing.T) {
	dir, _ := buildExport(t)
	path := filepath.Join(dir, "records.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	reordered := append([][]byte{}, lines...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	output := bytes.Join(reordered, []byte{'\n'})
	if err := os.WriteFile(path, append(output, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err == nil {
		t.Fatal("reordered records package was accepted")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

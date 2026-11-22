package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndChecksumOrder(t *testing.T) {
	dir := t.TempDir()
	manifest, err := Write(dir, Bundle{
		Events:      []any{map[string]any{"sequence": 1}},
		Decisions:   []any{map[string]any{"outcome": "replay"}},
		Gaps:        []any{map[string]any{"kind": "sequence_gap"}},
		Checkpoints: []any{map[string]any{"segment_id": 1}},
		ReplayCount: 1,
		Degraded:    true,
		CreatedAtMs: 42,
		Config:      json.RawMessage(`{"validity_window_ms":300000}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.EventCount != 1 || manifest.DecisionCount != 1 ||
		manifest.GapCount != 1 || manifest.CheckpointCount != 1 {
		t.Fatalf("manifest counts wrong: %+v", manifest)
	}
	wantOrder := []string{FileEvents, FileDecisions, FileGaps, FileCheckpoints}
	for i, name := range wantOrder {
		if manifest.Files[i].Name != name {
			t.Fatalf("file order %d = %s, want %s", i, manifest.Files[i].Name, name)
		}
		if manifest.Files[i].Lines != 1 || manifest.Files[i].Bytes == 0 {
			t.Fatalf("checksum record wrong: %+v", manifest.Files[i])
		}
	}
	for _, name := range append(wantOrder, FileManifest) {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing exported file %s: %v", name, err)
		}
	}
}

func TestWriteEmptyBundle(t *testing.T) {
	dir := t.TempDir()
	manifest, err := Write(dir, Bundle{Config: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.EventCount != 0 || manifest.DecisionCount != 0 {
		t.Fatal("empty bundle should report zero rows")
	}
	for _, fc := range manifest.Files {
		if fc.Lines != 0 {
			t.Fatalf("%s expected zero lines", fc.Name)
		}
	}
}

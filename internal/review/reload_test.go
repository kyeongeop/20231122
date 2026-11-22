package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"example.com/replay-review/internal/export"
	"example.com/replay-review/internal/model"
)

func TestVerifyBundleDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	rows := []any{
		model.Decision{Sequence: 1, DeviceID: "a", Outcome: model.OutcomeOK},
	}
	manifest, err := export.Write(dir, export.Bundle{
		Decisions: rows,
		Config:    json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(dir); err != nil {
		t.Fatalf("clean bundle failed verification: %v", err)
	}

	// Tamper with a decision line; the manifest checksum must catch it.
	path := filepath.Join(dir, export.FileDecisions)
	if err := os.WriteFile(path,
		[]byte(`{"sequence":1,"device_id":"a","outcome":"replay"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(dir); err == nil {
		t.Fatal("tampered bundle passed verification")
	}

	// Restore the file and confirm verification passes again.
	raw, _ := json.Marshal(rows[0])
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	rechecked, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("restored bundle failed: %v", err)
	}
	if rechecked.DecisionCount != manifest.DecisionCount {
		t.Fatal("manifest decision count changed on reload")
	}
}

func TestLoadJSONLPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.jsonl")
	content := "" +
		`{"sequence":1,"device_id":"a","code":"C","user_id":"u","outcome":"ok"}` + "\n" +
		`{"sequence":2,"device_id":"b","code":"C","user_id":"u","outcome":"replay"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := LoadJSONL[ReplayRow](path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Sequence != 1 || rows[1].Outcome != model.OutcomeReplay {
		t.Fatalf("order not preserved: %+v", rows)
	}
}

func TestCompareDecisionsReportsMismatch(t *testing.T) {
	a := []ReplayRow{{Sequence: 1, Outcome: model.OutcomeOK}}
	b := []ReplayRow{{Sequence: 1, Outcome: model.OutcomeReplay}}
	if err := CompareDecisions(a, b); err == nil {
		t.Fatal("expected mismatch error")
	}
	if err := CompareDecisions(a, a); err != nil {
		t.Fatalf("identical rows mismatched: %v", err)
	}
	gapA := []model.Gap{{Kind: model.GapSequence, DeviceID: "a", MissingFrom: 3}}
	gapB := []model.Gap{{Kind: model.GapSequence, DeviceID: "b", MissingFrom: 3}}
	if err := CompareGaps(gapA, gapB); err == nil {
		t.Fatal("expected gap mismatch error")
	}
}

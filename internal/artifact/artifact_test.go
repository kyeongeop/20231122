package artifact_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"corpusd/internal/artifact"
	"corpusd/internal/model"
	"corpusd/internal/pipeline"
	"corpusd/internal/store"
)

func TestExportLoadVerifyAndFieldOrder(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeFiles(t, corpusDir, map[string]string{
		"a":        "repeat",
		"b-replay": "repeat",
		"c":        "other",
		"nested/d": "nested",
	})
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := model.Config{
		Schema: model.SchemaVersion, BaseTimeUTC: "2026-01-01T00:00:00Z",
		SampleIntervalMS: 1000, ClockSkewMS: 1500,
		MemoryBudgetBytes: 1 << 20, MaxInputBytes: 1 << 20, CheckpointEvery: 1,
	}
	if _, err := pipeline.New(st, pipeline.Params{
		RunID: "export", CorpusDir: corpusDir, Config: cfg,
	}).Run(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "export")
	manifest, err := artifact.WriteExport(st, "export", out)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RecordCount != 4 || !manifest.Finalized || !manifest.ComparisonsPass {
		t.Fatalf("bad manifest: %+v", manifest)
	}
	report, err := artifact.VerifyExport(out)
	if err != nil {
		t.Fatal(err)
	}
	if report.Records != 4 || !report.FinalCompared {
		t.Fatalf("bad report: %+v", report)
	}
	loaded, err := artifact.LoadExport(out)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != len(loaded.Records) {
		t.Fatalf("reload lost records")
	}
	for i, rec := range loaded.Records {
		if err := artifact.CheckOrder(lines[i], model.RecordFields); err != nil {
			t.Fatalf("record %d order: %v", i+1, err)
		}
		again, err := model.MarshalRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, lines[i]) {
			t.Fatalf("record %d changed after reload", i+1)
		}
	}
}

func TestVerifyDetectsTamperedInput(t *testing.T) {
	dir, out := exportFixture(t)
	if _, err := artifact.VerifyExport(out); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(out, "inputs", "a")
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, append(data, '!'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.VerifyExport(out); err == nil {
		t.Fatal("tampered input was accepted")
	}
	_ = dir
}

func TestPausedExportVerifiesWithoutFinalComparison(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeFiles(t, corpusDir, map[string]string{
		"a": "one", "b": "two", "c": "three",
	})
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := model.Config{
		Schema: model.SchemaVersion, BaseTimeUTC: "2026-01-01T00:00:00Z",
		SampleIntervalMS: 1000, ClockSkewMS: 1500,
		MemoryBudgetBytes: 1 << 20, MaxInputBytes: 1 << 20, CheckpointEvery: 1,
	}
	summary, err := pipeline.New(st, pipeline.Params{
		RunID: "partial", CorpusDir: corpusDir, Config: cfg, PauseAfter: 1,
	}).Run()
	if err != nil || !summary.Paused {
		t.Fatalf("pause: %+v %v", summary, err)
	}
	out := filepath.Join(dir, "partial-export")
	manifest, err := artifact.WriteExport(st, "partial", out)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Finalized {
		t.Fatal("paused export marked finalized")
	}
	if _, err := artifact.VerifyExport(out); err != nil {
		t.Fatal(err)
	}
}

func TestCheckOrderRejectsReorderedFields(t *testing.T) {
	record := model.Record{
		Schema: model.SchemaVersion, RecordType: model.RecordType, RunID: "r", Seq: 1,
		ObjectID:  "sha256:" + strings.Repeat("a", 64),
		InputName: "a", InputSHA256: strings.Repeat("a", 64), InputBytes: 1,
		Observations: []model.ClockObservation{
			{DeviceID: "device-a", ClockRole: "primary"},
			{DeviceID: "device-b", ClockRole: "secondary"},
		},
		Mode: model.ModeFull, Decision: model.DecisionAnalyzed,
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.CheckOrder(data, model.RecordFields); err != nil {
		t.Fatal(err)
	}
	reordered := bytes.Replace(data,
		[]byte(`{"schema":"corpusd/v1","record_type":"fuzz_corpus_object"`),
		[]byte(`{"record_type":"fuzz_corpus_object","schema":"corpusd/v1"`), 1)
	if err := artifact.CheckOrder(reordered, model.RecordFields); err == nil {
		t.Fatal("reordered fields were accepted")
	}
}

func exportFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeFiles(t, corpusDir, map[string]string{
		"a": "one", "b": "two",
	})
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := model.Config{
		Schema: model.SchemaVersion, BaseTimeUTC: "2026-01-01T00:00:00Z",
		SampleIntervalMS: 1000, ClockSkewMS: 1500,
		MemoryBudgetBytes: 1 << 20, MaxInputBytes: 1 << 20, CheckpointEvery: 1,
	}
	if _, err := pipeline.New(st, pipeline.Params{
		RunID: "tamper", CorpusDir: corpusDir, Config: cfg,
	}).Run(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "export")
	if _, err := artifact.WriteExport(st, "tamper", out); err != nil {
		t.Fatal(err)
	}
	return dir, out
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

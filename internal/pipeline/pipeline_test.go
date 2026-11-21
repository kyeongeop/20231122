package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"corpusd/internal/model"
	"corpusd/internal/store"
)

func TestPauseResumeMatchesUninterruptedRun(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeCorpus(t, corpusDir)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := testConfig()
	base, err := New(st, Params{RunID: "baseline", CorpusDir: corpusDir, Config: cfg}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if base.Status != "completed" || !base.FinalCompared {
		t.Fatalf("baseline summary: %+v", base)
	}

	p := Params{RunID: "paused", CorpusDir: corpusDir, Config: cfg, PauseAfter: 2}
	var paused model.RunSummary
	for i := 0; i < 3; i++ {
		paused, err = New(st, p).Run()
		if err != nil {
			t.Fatal(err)
		}
		if !paused.Paused {
			break
		}
	}
	if paused.Paused || paused.Status != "completed" {
		t.Fatalf("paused run did not finish: %+v", paused)
	}
	if !paused.RestoreCompared || !paused.FinalCompared {
		t.Fatalf("missing comparisons: %+v", paused)
	}
	if paused.ResultDigest != base.ResultDigest {
		t.Fatalf("pause changed result: base=%s paused=%s",
			base.ResultDigest, paused.ResultDigest)
	}

	records, err := st.Results("paused", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 {
		t.Fatalf("want 5 records, got %d", len(records))
	}
	if !records[1].Duplicate || records[1].DuplicateOfSeq != 1 {
		t.Fatalf("repeated object not linked: %+v", records[1])
	}
	if !records[1].Evidence.AnalysisReused {
		t.Fatalf("repeated object did not reuse analysis")
	}
	comparisons, err := st.Comparisons("paused")
	if err != nil {
		t.Fatal(err)
	}
	if len(comparisons) < 2 || !allComparisonsMatch(comparisons) {
		t.Fatalf("unexpected comparisons: %+v", comparisons)
	}
}

func TestResourceBudgetDegradesAndKeepsEvidence(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeCorpus(t, corpusDir)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := testConfig()
	cfg.MemoryBudgetBytes = 1
	summary, err := New(st, Params{RunID: "degraded", CorpusDir: corpusDir, Config: cfg}).Run()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != "completed_degraded" || !summary.Degraded || !summary.FinalCompared {
		t.Fatalf("unexpected degraded summary: %+v", summary)
	}
	records, err := st.Results("degraded", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.Mode != model.ModeDegraded || rec.DegradedReason == "" ||
			rec.Analysis.Features != 0 {
			t.Fatalf("record did not follow degraded path: %+v", rec)
		}
	}
	events, err := st.Events("degraded")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Kind == "resource_degraded" && event.Reason == "memory_budget_exhausted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing degradation evidence: %+v", events)
	}
}

func TestResumeRejectsChangedConfig(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeCorpus(t, corpusDir)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := testConfig()
	summary, err := New(st, Params{
		RunID: "cfg", CorpusDir: corpusDir, Config: cfg, PauseAfter: 1,
	}).Run()
	if err != nil || !summary.Paused {
		t.Fatalf("pause: %+v %v", summary, err)
	}
	cfg.ClockSkewMS++
	_, err = New(st, Params{RunID: "cfg", CorpusDir: corpusDir, Config: cfg}).Run()
	if err == nil {
		t.Fatal("changed config was accepted on resume")
	}
}

func TestPausedDegradedRunResumesWithoutRecoveringMode(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	writeCorpus(t, corpusDir)
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := testConfig()
	cfg.MemoryBudgetBytes = 1
	p := Params{RunID: "degraded-resume", CorpusDir: corpusDir, Config: cfg, PauseAfter: 2}
	var summary model.RunSummary
	for i := 0; i < 3; i++ {
		summary, err = New(st, p).Run()
		if err != nil {
			t.Fatal(err)
		}
		if !summary.Paused {
			break
		}
	}
	if summary.Paused || !summary.Degraded || !summary.RestoreCompared ||
		!summary.FinalCompared {
		t.Fatalf("degraded resume summary: %+v", summary)
	}
	records, err := st.Results("degraded-resume", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.Mode != model.ModeDegraded {
			t.Fatalf("mode recovered after resume: %+v", rec)
		}
	}
}

func testConfig() model.Config {
	return model.Config{
		Schema: model.SchemaVersion, BaseTimeUTC: "2026-01-01T00:00:00Z",
		SampleIntervalMS: 1000, ClockSkewMS: 1500,
		MemoryBudgetBytes: 1 << 20, MaxInputBytes: 1 << 20, CheckpointEvery: 1,
	}
}

func writeCorpus(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"a-seed":        "repeated object",
		"b-replay":      "repeated object",
		"c-other":       "different object",
		"nested/d-seed": "nested object",
		"e-final":       "final object",
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func allComparisonsMatch(comparisons []model.Comparison) bool {
	for _, c := range comparisons {
		if !c.Match {
			return false
		}
	}
	return true
}

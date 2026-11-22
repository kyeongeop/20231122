package pipeline

import (
	"path/filepath"
	"testing"

	"example.com/replay-review/internal/export"
	"example.com/replay-review/internal/model"
	"example.com/replay-review/internal/review"
	"example.com/replay-review/internal/store"
)

func fixedClock() int64 { return 1_700_001_000_000 }

func TestPauseResumeExportAndReview(t *testing.T) {
	dir := t.TempDir()
	cfg := model.DefaultConfig()
	cfg.MaxEvents = 3
	in := Fixture(cfg)

	// Segmented run: two budget-limited segments then a draining segment.
	segDB := filepath.Join(dir, "segmented.sqlite")
	st, err := store.Open(segDB)
	if err != nil {
		t.Fatal(err)
	}
	p := New(cfg, st, in.Events, fixedClock)
	var pausedSegments, totalProcessed int
	for i := 0; i < 10; i++ {
		report, err := p.Run()
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		totalProcessed += report.Result.Processed
		if report.Paused {
			pausedSegments++
		}
		if !report.Paused {
			break
		}
	}
	st.Close()
	if pausedSegments != 2 || totalProcessed != len(in.Events) {
		t.Fatalf("paused=%d processed=%d events=%d",
			pausedSegments, totalProcessed, len(in.Events))
	}

	// One-shot reference run against a fresh database.
	oneShotCfg := cfg
	oneShotCfg.MaxEvents = 0
	baseDB := filepath.Join(dir, "baseline.sqlite")
	baseStore, err := store.Open(baseDB)
	if err != nil {
		t.Fatal(err)
	}
	base := New(oneShotCfg, baseStore, in.Events, fixedClock)
	if _, err := base.Run(); err != nil {
		t.Fatal(err)
	}

	segStore, err := store.Open(segDB)
	if err != nil {
		t.Fatal(err)
	}
	defer segStore.Close()
	defer baseStore.Close()

	segDec, err := segStore.LoadDecisions()
	if err != nil {
		t.Fatal(err)
	}
	baseDec, err := baseStore.LoadDecisions()
	if err != nil {
		t.Fatal(err)
	}
	if err := review.CompareDecisions(baseDec, segDec); err != nil {
		t.Fatal(err)
	}
	segGaps, err := segStore.LoadGaps()
	if err != nil {
		t.Fatal(err)
	}
	baseGaps, err := baseStore.LoadGaps()
	if err != nil {
		t.Fatal(err)
	}
	if err := review.CompareGaps(baseGaps, segGaps); err != nil {
		t.Fatal(err)
	}

	// Export both runs and verify the bundles independently.
	segBundle := filepath.Join(dir, "seg-bundle")
	baseBundle := filepath.Join(dir, "base-bundle")
	if err := exportBundle(t, segStore, segBundle); err != nil {
		t.Fatal(err)
	}
	if err := exportBundle(t, baseStore, baseBundle); err != nil {
		t.Fatal(err)
	}
	if _, err := review.VerifyBundle(segBundle); err != nil {
		t.Fatalf("verify segmented bundle: %v", err)
	}

	// Reloaded JSONL rows must match the SQLite projection in value and order.
	reloaded, err := review.LoadJSONL[review.ReplayRow](
		filepath.Join(segBundle, export.FileDecisions))
	if err != nil {
		t.Fatal(err)
	}
	if err := review.CompareDecisions(segDec, reloaded); err != nil {
		t.Fatalf("round-trip mismatch: %v", err)
	}

	replays, err := segStore.CountReplay()
	if err != nil {
		t.Fatal(err)
	}
	if replays != 1 {
		t.Fatalf("replays = %d, want 1", replays)
	}
}

func exportBundle(t *testing.T, st *store.Store, dir string) error {
	t.Helper()
	events, err := st.LoadEvents()
	if err != nil {
		return err
	}
	decisions, err := st.LoadDecisions()
	if err != nil {
		return err
	}
	gaps, err := st.LoadGaps()
	if err != nil {
		return err
	}
	checkpoints, err := st.LoadCheckpoints()
	if err != nil {
		return err
	}
	replays, err := st.CountReplay()
	if err != nil {
		return err
	}
	degraded, err := st.Degraded()
	if err != nil {
		return err
	}
	toAny := func(n int, at func(i int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = at(i)
		}
		return out
	}
	_, err = export.Write(dir, export.Bundle{
		Events:      toAny(len(events), func(i int) any { return events[i] }),
		Decisions:   toAny(len(decisions), func(i int) any { return decisions[i] }),
		Gaps:        toAny(len(gaps), func(i int) any { return gaps[i] }),
		Checkpoints: toAny(len(checkpoints), func(i int) any { return checkpoints[i] }),
		ReplayCount: replays,
		Degraded:    degraded,
		CreatedAtMs: fixedClock(),
	})
	return err
}

func TestResumeRejectsShorterStream(t *testing.T) {
	dir := t.TempDir()
	cfg := model.DefaultConfig()
	cfg.MaxEvents = 3
	in := Fixture(cfg)

	st, err := store.Open(filepath.Join(dir, "mismatch.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	p := New(cfg, st, in.Events, fixedClock)
	if _, err := p.Run(); err != nil {
		t.Fatal(err)
	}

	short := Fixture(cfg)
	short.Events = short.Events[:2]
	bad := New(cfg, st, short.Events, fixedClock)
	if _, err := bad.Run(); err == nil {
		t.Fatal("expected mismatch error when resuming with a shorter stream")
	}
}

func TestFaultInjectionPausesAndResumes(t *testing.T) {
	dir := t.TempDir()
	cfg := model.DefaultConfig()
	cfg.MaxEvents = 4
	in := Fixture(cfg)

	st, err := store.Open(filepath.Join(dir, "fault.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(cfg, st, in.Events, fixedClock).WithFaultPlan(FaultPlan{
		PauseAfterSegment: 2,
		PauseReason:       model.PauseFaultInjected,
	})

	first, err := p.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Paused || first.Reason != model.PauseBudgetExhausted {
		t.Fatalf("first segment = %+v", first)
	}
	second, err := p.Run()
	if err != nil {
		t.Fatal(err)
	}
	if !second.Paused || second.Reason != model.PauseFaultInjected || second.Result.Processed != 0 {
		t.Fatalf("injected segment = %+v", second)
	}
	remaining, err := p.Remaining()
	if err != nil {
		t.Fatal(err)
	}
	if remaining != len(in.Events)-first.Result.Processed {
		t.Fatalf("remaining = %d", remaining)
	}

	// Drain without further faults.
	plain := New(cfg, st, in.Events, fixedClock)
	for {
		report, err := plain.Run()
		if err != nil {
			t.Fatal(err)
		}
		if !report.Paused {
			break
		}
	}
	remaining, err = plain.Remaining()
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("drain left %d events", remaining)
	}
}

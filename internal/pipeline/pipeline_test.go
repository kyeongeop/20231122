package pipeline

import (
	"path/filepath"
	"testing"

	"truncstream/internal/reconcile"
	"truncstream/internal/resource"
	"truncstream/internal/store"
	"truncstream/internal/stream"
)

func buildCaptures(t *testing.T, n int, truncate bool) (a, b []byte) {
	t.Helper()
	recsA := stream.GenRecords(reconcile.DeviceA, "obj-x", n, 1_700_000_000_000, 1000, 0)
	recsB := stream.GenRecords(reconcile.DeviceB, "obj-x", n, 1_700_000_000_000, 1000, 4_200)
	optA := stream.EncodeOptions{Compress: true}
	if truncate {
		full, err := stream.BuildStream(recsA, stream.EncodeOptions{Compress: true})
		if err != nil {
			t.Fatal(err)
		}
		optA.TruncateAt = len(full) - 5
	}
	var err error
	if a, err = stream.BuildStream(recsA, optA); err != nil {
		t.Fatal(err)
	}
	if b, err = stream.BuildStream(recsB, stream.EncodeOptions{Compress: true}); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func runToEnd(t *testing.T, dbPath, runID string, cfg Config) string {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(st)
	pa, pb, err := p.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	_, hash, err := p.Finalize(cfg, pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestResumeMatchesBaseline(t *testing.T) {
	capA, capB := buildCaptures(t, 21, true)
	budget := resource.DefaultBudget()

	baseHash := runToEnd(t, filepath.Join(t.TempDir(), "base.sqlite"), "run-base", Config{
		RunID: "run-base", ObjectID: "obj-x",
		CaptureA: capA, CaptureB: capB, Budget: budget, SuspendAfter: -1,
	})

	resDir := t.TempDir()
	resDB := filepath.Join(resDir, "res.sqlite")
	cfg := Config{
		RunID: "run-res", ObjectID: "obj-x",
		CaptureA: capA, CaptureB: capB, Budget: budget, SuspendAfter: 5,
	}

	st1, err := store.Open(resDB)
	if err != nil {
		t.Fatal(err)
	}
	p1 := New(st1)
	pa, pb, err := p1.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	suspended, err := p1.Process(cfg, pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	if !suspended {
		t.Fatal("expected suspension at checkpoint")
	}
	row, _ := st1.GetRun("run-res")
	if row.State != store.StateSuspended {
		t.Fatalf("state = %s want SUSPENDED", row.State)
	}
	if _, _, err := st1.LatestCheckpoint("run-res"); err != nil {
		t.Fatalf("checkpoint not persisted: %v", err)
	}
	st1.Close()

	// Reopen the exact artifact and continue.
	resHash := runToEnd(t, resDB, "run-res", cfg)
	if resHash != baseHash {
		t.Fatalf("resumed report %s != baseline %s", resHash, baseHash)
	}
}

func TestTruncationClassifiedAndEvidenced(t *testing.T) {
	capA, capB := buildCaptures(t, 15, true)
	db := filepath.Join(t.TempDir(), "t.sqlite")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(st)
	cfg := Config{RunID: "r", ObjectID: "obj-x", CaptureA: capA, CaptureB: capB,
		Budget: resource.DefaultBudget(), SuspendAfter: -1}
	pa, pb, err := p.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if pa.Error == nil || pa.Error.Class != stream.ErrClassLength {
		t.Fatalf("expected TRUNCATED_PAYLOAD, got %+v", pa.Error)
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Finalize(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	row, _ := st.GetRun("r")
	if !row.InputTruncated || row.ParseErrorClass != stream.ErrClassLength {
		t.Fatalf("run row did not record truncation: %+v", row)
	}
	for _, kind := range []string{
		store.EvidenceRawCaptureA, store.EvidenceRawCaptureB,
		store.EvidenceParseResultA, store.EvidenceParseResultB,
		store.EvidenceReport, store.EvidenceCheckpoint,
	} {
		rows, err := st.EvidenceByKind("r", kind)
		if err != nil || len(rows) == 0 {
			t.Fatalf("missing evidence %s: %v", kind, err)
		}
	}
}

func TestTightBudgetTriggersDegradation(t *testing.T) {
	capA, capB := buildCaptures(t, 30, false)
	db := filepath.Join(t.TempDir(), "d.sqlite")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(st)
	budget := resource.Budget{MaxTokens: 30, MaxBytes: 128, SampleEvery: 4}
	cfg := Config{RunID: "r", ObjectID: "obj-x", CaptureA: capA, CaptureB: capB,
		Budget: budget, SuspendAfter: -1}
	pa, pb, err := p.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	events, err := st.ListDegradation("r")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected degradation events under tight budget")
	}
	sawBailout := false
	for _, e := range events {
		if e.Level == resource.LevelBailout {
			sawBailout = true
		}
	}
	if !sawBailout {
		t.Fatalf("never reached bailout: %+v", events)
	}
	row, _ := st.GetRun("r")
	if row.DegradeLevel != resource.LevelBailout {
		t.Fatalf("final level = %d, want %d", row.DegradeLevel, resource.LevelBailout)
	}
}

func TestCheckpointRejectsTamperedInput(t *testing.T) {
	capA, capB := buildCaptures(t, 18, false)
	db := filepath.Join(t.TempDir(), "tamper.sqlite")
	cfg := Config{RunID: "r", ObjectID: "obj-x", CaptureA: capA, CaptureB: capB,
		Budget: resource.DefaultBudget(), SuspendAfter: 4}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	p := New(st)
	pa, pb, err := p.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Mutate capture A before resume; the fingerprint guard must reject it.
	tampered := append([]byte(nil), capA...)
	tampered[len(tampered)-2] ^= 0x01
	cfg.CaptureA = tampered
	st2, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	p2 := New(st2)
	pa2, pb2, err := p2.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Process(cfg, pa2, pb2); err == nil {
		t.Fatal("resume on tampered input should fail fingerprint check")
	}
}

func TestReopenSameArtifactResumesSafely(t *testing.T) {
	capA, capB := buildCaptures(t, 15, true)
	path := filepath.Join(t.TempDir(), "safe.sqlite")
	cfg := Config{RunID: "r", ObjectID: "obj-x", CaptureA: capA, CaptureB: capB,
		Budget: resource.DefaultBudget(), SuspendAfter: 4}

	phases := 3
	for phase := 0; phase < phases; phase++ {
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		p := New(st)
		phaseCfg := cfg
		if phase > 0 {
			// After proving the first suspension persists, continue to
			// completion instead of requesting another suspension.
			phaseCfg.SuspendAfter = -1
		}
		pa, pb, err := p.Start(phaseCfg)
		if err != nil {
			t.Fatal(err)
		}
		suspended, err := p.Process(phaseCfg, pa, pb)
		if err != nil {
			t.Fatalf("phase %d failed: %v", phase, err)
		}
		if !suspended {
			if _, _, err := p.Finalize(phaseCfg, pa, pb); err != nil {
				t.Fatal(err)
			}
			st.Close()
			break
		}
		st.Close()
	}

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	row, err := st.GetRun("r")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != store.StateCompleted {
		t.Fatalf("state = %s want COMPLETED", row.State)
	}
}

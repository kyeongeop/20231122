package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"truncstream/internal/export"
	"truncstream/internal/pipeline"
	"truncstream/internal/reconcile"
	"truncstream/internal/resource"
	"truncstream/internal/store"
	"truncstream/internal/stream"
)

type demoFlags struct {
	dir          string
	frames       int
	truncate     bool
	suspendAfter int64
	tightBudget  bool
}

func parseDemoFlags(args []string) demoFlags {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	d := demoFlags{dir: "artifacts/demo", frames: 24, suspendAfter: 6}
	fs.StringVar(&d.dir, "dir", d.dir, "output directory")
	fs.IntVar(&d.frames, "frames", d.frames, "frames per device feed")
	fs.BoolVar(&d.truncate, "truncate", true, "cut capture A short to exercise truncation")
	fs.Int64Var(&d.suspendAfter, "suspend-after", d.suspendAfter, "processed frames before suspend (-1 disables)")
	fs.BoolVar(&d.tightBudget, "tight-budget", false, "force resource exhaustion and degradation")
	_ = fs.Parse(args)
	return d
}

func cmdDemo(args []string) error {
	d := parseDemoFlags(args)
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return err
	}
	// Remove artifacts from previous invocations so a fresh demo never
	// silently resumes a run whose captures were regenerated in-process.
	for _, name := range []string{"baseline.sqlite", "baseline.sqlite-wal", "baseline.sqlite-shm",
		"resumable.sqlite", "resumable.sqlite-wal", "resumable.sqlite-shm",
		"review-bundle.tar", "review-bundle.tar.sha256"} {
		if err := os.Remove(filepath.Join(d.dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	objectID := "obj-repeater-7"
	recsA := stream.GenRecords(reconcile.DeviceA, objectID, d.frames, 1_700_000_000_000, 1000, 0)
	recsB := stream.GenRecords(reconcile.DeviceB, objectID, d.frames, 1_700_000_000_000, 1000, 4_200)

	optA := stream.EncodeOptions{Compress: true, TruncateAt: -1}
	if d.truncate {
		full, err := stream.BuildStream(recsA, stream.EncodeOptions{Compress: true})
		if err != nil {
			return err
		}
		// Cut inside a later frame so the parser reports TRUNCATED_PAYLOAD.
		optA.TruncateAt = len(full) - 7
	}
	capA, err := stream.BuildStream(recsA, optA)
	if err != nil {
		return err
	}
	capB, err := stream.BuildStream(recsB, stream.EncodeOptions{Compress: true})
	if err != nil {
		return err
	}

	budget := resource.DefaultBudget()
	if d.tightBudget {
		budget.MaxTokens = 40
		budget.MaxBytes = 256
	}

	// Baseline: one uninterrupted run.
	baseDB := filepath.Join(d.dir, "baseline.sqlite")
	baseHash, err := runOne(baseDB, pipeline.Config{
		RunID: "run-baseline", ObjectID: objectID,
		CaptureA: capA, CaptureB: capB, Budget: budget, SuspendAfter: -1,
	})
	if err != nil {
		return err
	}

	// Resumable: suspend mid stream, reopen the artifact, continue.
	resDB := filepath.Join(d.dir, "resumable.sqlite")
	resHash, suspended, err := runResumable(resDB, pipeline.Config{
		RunID: "run-resumed", ObjectID: objectID,
		CaptureA: capA, CaptureB: capB, Budget: budget, SuspendAfter: d.suspendAfter,
	})
	if err != nil {
		return err
	}

	stBase, err := store.Open(baseDB)
	if err != nil {
		return err
	}
	defer stBase.Close()
	st, err := store.Open(resDB)
	if err != nil {
		return err
	}
	defer st.Close()
	diff, err := pipeline.CompareAcrossStores(stBase, st, "run-baseline", "run-resumed")
	if err != nil {
		return err
	}
	events, err := st.ListDegradation("run-resumed")
	if err != nil {
		return err
	}
	runRow, err := st.GetRun("run-resumed")
	if err != nil {
		return err
	}

	reportJSON, _, err := st.GetReport("run-resumed")
	if err != nil {
		return err
	}
	bundlePath := filepath.Join(d.dir, "review-bundle.tar")
	mf, err := export.Build(export.Options{
		RunID:      "run-resumed",
		SQLitePath: resDB,
		ReportJSON: []byte(reportJSON),
		ReportSHA:  resHash,
		OutPath:    bundlePath,
		ExtraFiles: map[string][]byte{
			"capture_a.bin": capA,
			"capture_b.bin": capB,
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("baseline report sha256 : %s\n", baseHash)
	fmt.Printf("resumed  report sha256 : %s (suspended=%v)\n", resHash, suspended)
	fmt.Printf("reports equal          : %v\n", diff.ReportsEqual)
	fmt.Printf("differences            : %d\n", len(diff.Differences))
	fmt.Printf("truncation class       : %s (truncated=%v)\n", runRow.ParseErrorClass, runRow.InputTruncated)
	fmt.Printf("degradation events     : %d (final level=%d)\n", len(events), runRow.DegradeLevel)
	for _, e := range events {
		fmt.Printf("  - level %d %s: %s\n", e.Level, e.Reason, e.Detail)
	}
	fmt.Printf("bundle                 : %s [%d files, sha256=%s]\n",
		bundlePath, len(mf.Files), mf.BundleSHA256)
	return nil
}

func runOne(dbPath string, cfg pipeline.Config) (string, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer st.Close()
	p := pipeline.New(st)
	pa, pb, err := p.Start(cfg)
	if err != nil {
		return "", err
	}
	if _, err := p.Process(cfg, pa, pb); err != nil {
		return "", err
	}
	_, hash, err := p.Finalize(cfg, pa, pb)
	return hash, err
}

func runResumable(dbPath string, cfg pipeline.Config) (hash string, suspended bool, err error) {
	// Phase 1: open, start, suspend at checkpoint.
	st, err := store.Open(dbPath)
	if err != nil {
		return "", false, err
	}
	p := pipeline.New(st)
	pa, pb, err := p.Start(cfg)
	if err != nil {
		st.Close()
		return "", false, err
	}
	suspended, err = p.Process(cfg, pa, pb)
	if cerr := st.Close(); cerr != nil {
		return "", false, cerr
	}
	if err != nil {
		return "", false, err
	}

	// Phase 2: reopen artifact and continue from the persisted checkpoint.
	st2, err := store.Open(dbPath)
	if err != nil {
		return "", false, err
	}
	defer st2.Close()
	p2 := pipeline.New(st2)
	pa2, pb2, err := p2.Start(cfg)
	if err != nil {
		return "", false, err
	}
	again, err := p2.Process(cfg, pa2, pb2)
	if err != nil {
		return "", false, err
	}
	_, hash, err = p2.Finalize(cfg, pa2, pb2)
	return hash, suspended || again, err
}

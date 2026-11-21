package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"

	"krfix/internal/material"
	"krfix/internal/runner"
	"krfix/internal/store"
)

func runRun(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	sampleFilter := fs.String("sample", "", "only this sample name (empty = all pending)")
	phaseFilter := fs.String("phase", "", "vuln|fixed (empty = both)")
	redo := fs.Bool("redo", false, "re-run even jobs already marked done")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *phaseFilter {
	case "", runner.PhaseVuln, runner.PhaseFixed:
	default:
		return fmt.Errorf("--phase must be vuln or fixed")
	}

	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	if err := material.VerifyOriginal(ctx, layout, db); err != nil {
		return err
	}

	samples, err := store.ListSamples(ctx, db)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return errors.New("no samples imported; run 'krfix import' first")
	}

	cfg := runner.Config{
		WorkDir:     layout.Root,
		ReplayVuln:  layout.BuildDir + "/kr_replay_vuln",
		ReplayFixed: layout.BuildDir + "/kr_replay_fixed",
		EvidenceDir: layout.EvidenceDir,
	}
	phases := []string{runner.PhaseVuln, runner.PhaseFixed}
	if *phaseFilter != "" {
		phases = []string{*phaseFilter}
	}

	processed, skipped, interrupted := 0, 0, false
	for i := range samples {
		s := samples[i]
		if *sampleFilter != "" && s.Name != *sampleFilter {
			continue
		}
		for _, phase := range phases {
			if ctx.Err() != nil {
				interrupted = true
				break
			}
			if _, err := store.EnsureJob(ctx, db, s.ID, phase); err != nil {
				return err
			}
			state, err := store.JobState(ctx, db, s.Name, phase)
			if err != nil {
				return err
			}
			if state == "done" && *redo {
				if err := store.ReopenJob(ctx, db, s.ID, phase); err != nil {
					return err
				}
				state = "pending"
			}
			if state == "done" {
				skipped++
				fmt.Printf("skip  %-18s %-5s (done; use --redo to rerun)\n", s.Name, phase)
				continue
			}
			if err := executeOne(ctx, db, cfg, &s, phase); err != nil {
				if errors.Is(err, context.Canceled) {
					interrupted = true
					break
				}
				return err
			}
			processed++
		}
		if interrupted {
			break
		}
	}

	fmt.Printf("krfix: processed=%d skipped=%d\n", processed, skipped)
	if interrupted {
		fmt.Println("krfix: interrupted; progress committed to SQLite - rerun 'krfix run' to resume")
	}
	return nil
}

func executeOne(ctx context.Context, db *sql.DB, cfg runner.Config,
	s *store.Sample, phase string) error {
	jobID, err := store.EnsureJob(ctx, db, s.ID, phase)
	if err != nil {
		return err
	}
	job, err := store.ClaimJob(ctx, db, s.Name, phase)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	fmt.Printf("run   %-18s %-5s attempt=%d started=%s\n",
		s.Name, phase, job.Attempts, store.NowUTC())

	runID, err := store.InsertRun(ctx, db, jobID, job.Attempts)
	if err != nil {
		return err
	}

	res, err := runner.Replay(ctx, cfg, s, phase)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			_ = store.FinishJob(ctx, db, jobID, "interrupted")
			return err
		}
		_ = store.FinishJob(ctx, db, jobID, "error")
		return err
	}

	if err := store.FinishRun(ctx, db, runID, int64(res.ExitCode),
		res.DurationNS, res.Label); err != nil {
		return err
	}
	for _, ev := range []struct{ kind, path, note string }{
		{"stdout_log", res.StdoutLog, "libFuzzer replay stdout"},
		{"stderr_log", res.StderrLog, "libFuzzer replay stderr"},
		{"sample_copy", s.RawPath, "working copy of sample"},
	} {
		digest, err := runner.HashEvidence(ev.path)
		if err != nil {
			return err
		}
		if err := store.InsertEvidence(ctx, db, s.ID, runID,
			ev.kind, ev.path, digest, ev.note); err != nil {
			return err
		}
	}
	if err := store.FinishJob(ctx, db, jobID, "done"); err != nil {
		return err
	}
	fmt.Printf("done  %-18s %-5s exit=%d verdict=%s duration_ms=%d finished=%s\n",
		s.Name, phase, res.ExitCode, res.Label, res.DurationNS/1_000_000,
		store.NowUTC())
	return nil
}

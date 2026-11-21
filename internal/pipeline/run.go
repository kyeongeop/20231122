package pipeline

import (
	"fmt"
	"path/filepath"

	"corpusd/internal/corpus"
	"corpusd/internal/model"
)

func (r *Runner) Run() (model.RunSummary, error) {
	var summary model.RunSummary
	if r.p.RunID == "" {
		return summary, fmt.Errorf("run id is required")
	}
	if err := validateConfig(r.p.Config); err != nil {
		return summary, err
	}
	abs, err := filepath.Abs(r.p.CorpusDir)
	if err != nil {
		return summary, err
	}
	entries, fingerprint, err := corpus.Scan(abs)
	if err != nil {
		return summary, err
	}
	cfg := r.p.Config
	created, err := r.st.CreateRun(r.p.RunID, abs, fingerprint, cfg, entries, model.NowUTC())
	if err != nil {
		return summary, err
	}
	run, exists, err := r.st.Run(r.p.RunID)
	if err != nil {
		return summary, err
	}
	if !exists {
		return summary, fmt.Errorf("run %q was not loaded after creation", r.p.RunID)
	}
	if run.Status == "completed" || run.Status == "completed_degraded" {
		return summaryFromRun(run), nil
	}
	if run.Status == "failed" {
		return summary, fmt.Errorf("run %q is marked failed; inspect its evidence", r.p.RunID)
	}
	if run.CorpusFingerprint != fingerprint {
		return summary, fmt.Errorf("corpus changed since run creation: want %s got %s",
			run.CorpusFingerprint, fingerprint)
	}
	if !created {
		if run.Config != cfg {
			return summary, fmt.Errorf("run config changed; resume with the original --base-ts, skew, budgets and checkpoint interval")
		}
		entries, err = r.st.Entries(r.p.RunID)
		if err != nil {
			return summary, err
		}
		if got := corpus.Fingerprint(entries); got != run.CorpusFingerprint {
			return summary, fmt.Errorf("stored corpus order digest mismatch: want %s got %s",
				run.CorpusFingerprint, got)
		}
		r.p.CorpusDir = run.CorpusDir
	}

	base, err := model.ParseBaseTime(cfg.BaseTimeUTC)
	if err != nil {
		return summary, err
	}
	baseNS := base.UnixNano()
	st := newState(cfg)
	var records []model.Record
	completed := int64(0)
	var checkpointSeq int64

	cp, err := r.st.LatestCheckpoint(r.p.RunID)
	if err != nil {
		return summary, err
	}
	if cp != nil {
		records, err = r.st.Results(r.p.RunID, cp.Cursor)
		if err != nil {
			return summary, err
		}
		if err := checkContiguous(records, cp.Cursor); err != nil {
			return summary, err
		}
		after := model.ResultDigest(records)
		match := after == cp.ResultDigest
		if _, err := r.saveComparison("resume_restore", cp.ResultDigest, after,
			match, cp.Cursor, cp.Cursor,
			fmt.Sprintf("reloaded %d persisted records before resuming", len(records))); err != nil {
			return summary, err
		}
		if !match {
			_ = r.fail(cp.Cursor, "checkpoint result digest does not match persisted records")
			return summary, fmt.Errorf("restore comparison failed: checkpoint=%s restored=%s",
				cp.ResultDigest, after)
		}
		summary.RestoreCompared = true
		st.restore(records)
		completed = cp.Cursor
		checkpointSeq = cp.Seq
		_, _ = r.appendEvent(model.Event{
			Kind: "resume", Cursor: completed, Mode: stateMode(st.degraded),
			Reason: "checkpoint_restore_verified", CheckpointSeq: cp.Seq,
			ResultDigest: after,
			Detail: fmt.Sprintf("resumed from checkpoint %d with %d records; digest verified",
				cp.Seq, len(records)),
		})
	} else {
		_, _ = r.appendEvent(model.Event{
			Kind: "run_started", Cursor: 0, Mode: model.ModeFull,
			Reason: "new_run",
			Detail: fmt.Sprintf("snapshotted %d corpus entries in lexical order; device-b skew=%dms; canonical base=%s",
				len(entries), cfg.ClockSkewMS, cfg.BaseTimeUTC),
		})
	}
	if err := r.st.UpdateProgress(r.p.RunID, "running", completed, st.degraded,
		model.ResultDigest(records), model.NowUTC()); err != nil {
		return summary, err
	}

	processedThisCall := int64(0)
	saveCheckpoint := func(reason string) error {
		checkpointSeq++
		cp := model.NewCheckpoint(r.p.RunID)
		cp.Seq = checkpointSeq
		cp.Cursor = completed
		cp.CompletedCount = completed
		cp.Degraded = st.degraded
		cp.Mode = stateMode(st.degraded)
		cp.ResultDigest = model.ResultDigest(records)
		cp.Reason = reason
		cp.TSUTC = model.NowUTC()
		if err := r.st.SaveCheckpoint(cp); err != nil {
			return err
		}
		return r.st.UpdateProgress(r.p.RunID, "running", completed, st.degraded,
			cp.ResultDigest, cp.TSUTC)
	}

	for completed < int64(len(entries)) {
		if r.p.PauseAfter > 0 && processedThisCall >= r.p.PauseAfter {
			if err := saveCheckpoint("pause_after_limit"); err != nil {
				return summary, err
			}
			digest := model.ResultDigest(records)
			_, _ = r.appendEvent(model.Event{
				Kind: "pause", Cursor: completed, Mode: stateMode(st.degraded),
				Reason: "pause_after_limit", CheckpointSeq: checkpointSeq,
				ResultDigest: digest,
				Detail: fmt.Sprintf("paused after %d entries processed in this invocation",
					processedThisCall),
			})
			if err := r.st.UpdateProgress(r.p.RunID, "paused", completed,
				st.degraded, digest, model.NowUTC()); err != nil {
				return summary, err
			}
			summary = model.RunSummary{
				RunID: r.p.RunID, Status: "paused", TotalEntries: int64(len(entries)),
				CompletedCount: completed, Paused: true, Degraded: st.degraded,
				Cursor: completed, CheckpointSeq: checkpointSeq, ResultDigest: digest,
				RestoreCompared: summary.RestoreCompared,
			}
			return summary, nil
		}

		entry := entries[completed]
		rec, justDegraded, reason, err := r.processOne(entry, r.p.RunID, cfg, baseNS, st)
		if err != nil {
			_ = r.fail(completed, err.Error())
			return summary, err
		}
		if err := r.st.SaveResult(r.p.RunID, rec, model.NowUTC()); err != nil {
			_ = r.fail(completed, err.Error())
			return summary, err
		}
		records = append(records, rec)
		completed = rec.Seq
		processedThisCall++
		if justDegraded {
			_, _ = r.appendEvent(model.Event{
				Kind: "resource_degraded", Cursor: completed, Mode: model.ModeDegraded,
				Reason: reason, ObjectID: rec.ObjectID, InputName: rec.InputName,
				InputSHA256: rec.InputSHA256,
				Detail: fmt.Sprintf("budget=%d remaining=%d estimate=%d; fallback=metadata_only",
					rec.Evidence.MemoryBudgetBytes, rec.Evidence.MemoryRemainingBytes,
					rec.Evidence.EstimatedBytes),
			})
		}
		if cfg.CheckpointEvery > 0 && processedThisCall%int64(cfg.CheckpointEvery) == 0 {
			if err := saveCheckpoint("checkpoint_interval"); err != nil {
				return summary, err
			}
		}
	}

	if err := saveCheckpoint("final_state"); err != nil {
		return summary, err
	}
	rebuilt, err := r.rebuild(entries, cfg, baseNS)
	if err != nil {
		_ = r.fail(completed, "final recomputation: "+err.Error())
		return summary, err
	}
	before := model.ResultDigest(records)
	after := model.ResultDigest(rebuilt)
	match := before == after && sameRecordDigests(records, rebuilt)
	if _, err := r.saveComparison("final_recompute", before, after, match,
		completed, checkpointSeq,
		fmt.Sprintf("recomputed %d records from the immutable corpus snapshot", len(rebuilt))); err != nil {
		return summary, err
	}
	if !match {
		_ = r.fail(completed, "final recomputation digest mismatch")
		return summary, fmt.Errorf("final recomputation mismatch: persisted=%s rebuilt=%s",
			before, after)
	}
	summary.FinalCompared = true
	status := "completed"
	if st.degraded {
		status = "completed_degraded"
	}
	if err := r.st.UpdateProgress(r.p.RunID, status, completed, st.degraded,
		before, model.NowUTC()); err != nil {
		return summary, err
	}
	_, _ = r.appendEvent(model.Event{
		Kind: "complete", Cursor: completed, Mode: stateMode(st.degraded),
		Reason: status, CheckpointSeq: checkpointSeq, ResultDigest: before,
		Detail: fmt.Sprintf("processed %d entries; restore_compared=%t final_compared=true",
			completed, summary.RestoreCompared),
	})
	return model.RunSummary{
		RunID: r.p.RunID, Status: status, TotalEntries: int64(len(entries)),
		CompletedCount: completed, Degraded: st.degraded, Cursor: completed,
		CheckpointSeq: checkpointSeq, ResultDigest: before,
		RestoreCompared: summary.RestoreCompared, FinalCompared: true,
	}, nil
}

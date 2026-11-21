package pipeline

import (
	"fmt"
	"time"

	"corpusd/internal/corpus"
	"corpusd/internal/model"
	"corpusd/internal/store"
)

func validateConfig(cfg model.Config) error {
	maxMillis := int64(^uint64(0)>>1) / int64(time.Millisecond)
	if cfg.Schema != model.SchemaVersion {
		return fmt.Errorf("unsupported config schema %q", cfg.Schema)
	}
	if cfg.SampleIntervalMS <= 0 {
		return fmt.Errorf("sample interval must be positive")
	}
	if cfg.SampleIntervalMS > maxMillis {
		return fmt.Errorf("sample interval is too large")
	}
	if cfg.ClockSkewMS > maxMillis || cfg.ClockSkewMS < -maxMillis {
		return fmt.Errorf("clock skew is too large")
	}
	if cfg.MemoryBudgetBytes < 0 {
		return fmt.Errorf("memory budget cannot be negative")
	}
	if cfg.CheckpointEvery < 0 {
		return fmt.Errorf("checkpoint interval cannot be negative")
	}
	if _, err := model.ParseBaseTime(cfg.BaseTimeUTC); err != nil {
		return err
	}
	return nil
}

func stateMode(degraded bool) string {
	if degraded {
		return model.ModeDegraded
	}
	return model.ModeFull
}

func summaryFromRun(run store.RunState) model.RunSummary {
	return model.RunSummary{
		RunID:          run.RunID,
		Status:         run.Status,
		TotalEntries:   run.TotalEntries,
		CompletedCount: run.Cursor,
		Degraded:       run.Degraded,
		Cursor:         run.Cursor,
		ResultDigest:   run.ResultDigest,
	}
}

func checkContiguous(records []model.Record, cursor int64) error {
	if int64(len(records)) != cursor {
		return fmt.Errorf("checkpoint cursor %d does not match %d persisted records",
			cursor, len(records))
	}
	for i, rec := range records {
		if rec.Seq != int64(i+1) {
			return fmt.Errorf("result order corrupt at index %d: seq=%d", i, rec.Seq)
		}
	}
	return nil
}

func sameRecordDigests(a, b []model.Record) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if model.RecordDigest(a[i]) != model.RecordDigest(b[i]) {
			return false
		}
	}
	return true
}

func (r *Runner) appendEvent(e model.Event) (int64, error) {
	e.Schema = model.SchemaVersion
	e.RecordType = "event"
	e.RunID = r.p.RunID
	if e.TSUTC == "" {
		e.TSUTC = model.NowUTC()
	}
	return r.st.AppendEvent(e)
}

func (r *Runner) saveComparison(phase, before, after string, match bool,
	cursor, checkpointSeq int64, detail string) (int64, error) {
	c := model.Comparison{
		Schema: model.SchemaVersion, RecordType: "comparison",
		RunID: r.p.RunID, Phase: phase, BeforeDigest: before,
		AfterDigest: after, Match: match, ComparedRecords: cursor,
		Cursor: cursor, TSUTC: model.NowUTC(), Detail: detail,
	}
	seq, err := r.st.AppendComparison(c)
	if err != nil {
		return 0, err
	}
	_, _ = r.appendEvent(model.Event{
		Kind: "comparison", Cursor: cursor,
		Reason: phase, CheckpointSeq: checkpointSeq, ResultDigest: after,
		Detail: fmt.Sprintf("%s match=%t before=%s after=%s",
			phase, match, before, after),
	})
	return seq, nil
}

func (r *Runner) fail(cursor int64, detail string) error {
	_, err := r.appendEvent(model.Event{
		Kind: "failed", Cursor: cursor, Reason: "processing_failure",
		Detail: detail,
	})
	if updateErr := r.st.UpdateProgress(r.p.RunID, "failed", cursor,
		false, "", model.NowUTC()); updateErr != nil {
		return updateErr
	}
	return err
}

func (r *Runner) rebuild(entries []corpus.Entry, cfg model.Config, baseNS int64) ([]model.Record, error) {
	st := newState(cfg)
	out := make([]model.Record, 0, len(entries))
	for _, entry := range entries {
		rec, _, _, err := r.processOne(entry, r.p.RunID, cfg, baseNS, st)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

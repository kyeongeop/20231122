package runner

import (
	"encoding"
	"errors"
	"fmt"

	"tve/internal/store"
)

// Run processes records until completion, pause, or resource exhaustion.
// It returns nil on completion, ErrPaused on a planned pause, and
// ErrResourceExhausted when the output budget is exceeded.
func (r *Runner) Run() error {
	if r.resumeNote != "" {
		if err := r.Store.SaveEvent(store.Event{
			JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindResumed,
			RecordIndex: r.next,
			RawOffset:   r.rawOff(int(r.next)),
			Detail:      r.resumeNote,
		}); err != nil {
			return err
		}
		r.resumeNote = ""
	}
	for r.next < int64(r.Params.Repeat) {
		i := int(r.next)
		out, evs, err := RecordOutput(r.Params, r.Material, i, r.degraded)
		if err != nil {
			// Hard failure path: record evidence, emit placeholder, continue.
			r.degradedN++
			if err := r.Store.SaveEvent(store.Event{
				JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindHardFailure,
				RecordIndex: r.next,
				RawOffset:   r.rawOff(i),
				Detail:      err.Error(),
			}); err != nil {
				return err
			}
			out = []byte("DEGRADED\n")
		}
		for _, e := range evs {
			r.degradedN++
			if err := r.Store.SaveEvent(store.Event{
				JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindDegraded,
				RecordIndex: r.next,
				RawOffset:   r.rawOff(i),
				Detail:      fmt.Sprintf("%s at template-offset %d: %s", e.Kind, e.Offset, e.Detail),
			}); err != nil {
				return err
			}
		}
		r.runHash.Write(out)
		r.batchHash.Write(out)
		r.batchBytes += int64(len(out))
		r.outBytes += int64(len(out))
		r.next++
		r.processed++

		if r.processed%int64(r.Params.BatchSize) == 0 {
			if err := r.flushBatch(); err != nil {
				return err
			}
		}
		if r.Params.OutputBudget > 0 && r.outBytes > r.Params.OutputBudget {
			if r.degraded {
				return errors.New("output budget exceeded even in degraded mode")
			}
			if err := r.checkpoint(); err != nil {
				return err
			}
			if err := r.Store.SaveEvent(store.Event{
				JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindResource,
				RecordIndex: r.next,
				RawOffset:   r.rawOff(i),
				Detail:      fmt.Sprintf("out-bytes=%d budget=%d", r.outBytes, r.Params.OutputBudget),
			}); err != nil {
				return err
			}
			return r.stop("exhausted", ErrResourceExhausted)
		}
		if r.Params.PauseAfter > 0 && r.processed == int64(r.Params.PauseAfter) {
			if err := r.checkpoint(); err != nil {
				return err
			}
			if err := r.Store.SaveEvent(store.Event{
				JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindPaused,
				RecordIndex: r.next,
				RawOffset:   r.rawOff(i),
				Detail:      fmt.Sprintf("pause-after=%d", r.Params.PauseAfter),
			}); err != nil {
				return err
			}
			return r.stop("paused", ErrPaused)
		}
	}
	if err := r.flushBatch(); err != nil {
		return err
	}
	if err := r.checkpoint(); err != nil {
		return err
	}
	if err := r.Store.SaveEvent(store.Event{
		JobID: r.JobID, TsUTC: r.utc(), Kind: store.KindCompleted,
		RecordIndex: r.next,
		RawOffset:   0,
		Detail:      "final-hash=" + r.FinalHash(),
	}); err != nil {
		return err
	}
	return r.stop("completed", nil)
}

func (r *Runner) stop(status string, runErr error) error {
	if err := r.Store.SetJobStatus(r.JobID, status); err != nil {
		return err
	}
	return runErr
}

func (r *Runner) flushBatch() error {
	if r.batchBytes == 0 {
		return nil
	}
	err := r.Store.SaveBatch(store.Batch{
		JobID:      r.JobID,
		StartIndex: r.batchStart,
		EndIndex:   r.next - 1,
		OutSHA256:  fmt.Sprintf("%x", r.batchHash.Sum(nil)),
		OutBytes:   r.batchBytes,
		RawOffset:  r.batchRawOff,
		TsUTC:      r.utc(),
	})
	if err != nil {
		return err
	}
	r.batchHash.Reset()
	r.batchStart = r.next
	r.batchRawOff = r.rawOff(int(r.next))
	r.batchBytes = 0
	return nil
}

func (r *Runner) checkpoint() error {
	state, err := r.runHash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize hash state: %w", err)
	}
	bstate, err := r.batchHash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize batch hash state: %w", err)
	}
	r.ckptSeq++
	return r.Store.SaveCheckpoint(store.Checkpoint{
		JobID: r.JobID, Seq: r.ckptSeq, SavedUTC: r.utc(),
		NextIndex: r.next, HashState: state,
		BatchState: bstate, BatchBytes: r.batchBytes, BatchStart: r.batchStart,
		BatchRawOff: r.batchRawOff,
		OutBytes:    r.outBytes,
		Processed:   r.processed, Degraded: r.degradedN,
	})
}

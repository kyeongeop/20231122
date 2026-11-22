// Package pipeline implements the pausable truncated-stream processor.
// Processing advances frame by frame and only suspends at frames flagged as
// checkpoints, so a resumed run never duplicates or skips a frame. Every
// suspension writes a sha256-keyed ProcessingState into SQLite; resume
// reloads that exact state and continues. A full uninterrupted run and a
// suspended/resumed run over the same capture must converge on identical
// reports (compared by hash).
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"truncstream/internal/reconcile"
	"truncstream/internal/resource"
	"truncstream/internal/store"
	"truncstream/internal/stream"
)

// Config captures one pipeline invocation.
type Config struct {
	RunID    string
	ObjectID string
	CaptureA []byte
	CaptureB []byte
	Budget   resource.Budget
	// SuspendAfter >= 0 requests a suspension once that many data frames
	// have been processed and a checkpoint frame is reached. -1 disables.
	SuspendAfter int64
}

// Pipeline ties storage, budgets and parsing together.
type Pipeline struct {
	st *store.Store
}

// New wires a pipeline to an opened store.
func New(st *store.Store) *Pipeline { return &Pipeline{st: st} }

// Stage labels used inside ProcessingState.
const (
	StageParsing     = "PARSING"
	StageProcessing  = "PROCESSING"
	StageReconciling = "RECONCILING"
	StageDone        = "DONE"
)

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Start parses both captures, stores raw evidence and inserts a run row.
// It is safe to call again on resume: existing evidence is left untouched.
func (p *Pipeline) Start(cfg Config) (stream.ParseResult, stream.ParseResult, error) {
	pa := stream.Parse(cfg.CaptureA)
	pb := stream.Parse(cfg.CaptureB)

	parseClass := ""
	switch {
	case pa.Error != nil:
		parseClass = pa.Error.Class
	case pb.Error != nil:
		parseClass = pb.Error.Class
	}

	if _, err := p.st.GetRun(cfg.RunID); errors.Is(err, store.ErrNotFound) {
		row := store.RunRow{
			RunID:           cfg.RunID,
			ObjectID:        cfg.ObjectID,
			State:           store.StateNew,
			InputSHA256:     digest(append(append([]byte(nil), cfg.CaptureA...), cfg.CaptureB...)),
			InputSize:       int64(len(cfg.CaptureA) + len(cfg.CaptureB)),
			InputTruncated:  parseClass == stream.ErrClassLength || parseClass == stream.ErrClassHeader,
			ParseErrorClass: parseClass,
		}
		if err := p.st.CreateRun(row, cfg.Budget.MaxTokens, cfg.Budget.MaxBytes); err != nil {
			return pa, pb, err
		}
		if _, err := p.st.AddEvidence(cfg.RunID, store.EvidenceRawCaptureA, cfg.CaptureA); err != nil {
			return pa, pb, err
		}
		if _, err := p.st.AddEvidence(cfg.RunID, store.EvidenceRawCaptureB, cfg.CaptureB); err != nil {
			return pa, pb, err
		}
		paJSON, _ := json.Marshal(pa)
		pbJSON, _ := json.Marshal(pb)
		if _, err := p.st.AddEvidence(cfg.RunID, store.EvidenceParseResultA, paJSON); err != nil {
			return pa, pb, err
		}
		if _, err := p.st.AddEvidence(cfg.RunID, store.EvidenceParseResultB, pbJSON); err != nil {
			return pa, pb, err
		}
	} else if err != nil {
		return pa, pb, err
	}
	return pa, pb, nil
}

// Process runs the frame loop until completion, suspension (checkpoint with
// enough processed frames), or bailout (resource level 3). The returned
// suspended flag distinguishes "paused, resume later" from "finished".
func (p *Pipeline) Process(cfg Config, pa, pb stream.ParseResult) (suspended bool, err error) {
	mon := resource.NewMonitor(cfg.Budget)
	st := store.ProcessingState{
		RunID:            cfg.RunID,
		NextSeq:          0,
		ConsumedFrames:   0,
		Accumulator:      map[string]int64{},
		SeenCheckpoints:  []int64{},
		InputFingerprint: reconcile.Fingerprint(pa, pb),
		Stage:            StageProcessing,
	}
	if cp, saved, lerr := p.st.LatestCheckpoint(cfg.RunID); lerr == nil {
		if saved.InputFingerprint != st.InputFingerprint {
			return false, fmt.Errorf("input fingerprint changed since checkpoint %d: %s != %s",
				cp.Seq, saved.InputFingerprint, st.InputFingerprint)
		}
		st = saved
		// Replay the persisted consumption so the resource monitor starts
		// at the same pressure level and does not re-emit transitions that
		// were already recorded as evidence before the suspension.
		row, rerr := p.st.GetRun(cfg.RunID)
		if rerr != nil {
			return false, rerr
		}
		mon.Replay(row.TokensUsed, row.BytesUsed, saved.DegradeLevel)
	} else if !errors.Is(lerr, store.ErrNotFound) {
		return false, lerr
	}

	frames := pa.Frames
	total := int64(len(frames))
	state := store.StateRunning
	for idx := st.NextSeq; idx < total; idx++ {
		frame := frames[idx]
		if !mon.ShouldProcess(idx) {
			continue
		}
		tokens := int64(8 + len(frame.Payload))
		mon.Consume(tokens, int64(len(frame.Payload)))

		for _, tr := range mon.NewTransitions() {
			if derr := p.st.AddDegradation(cfg.RunID, tr.To, tr.Reason, tr.Detail); derr != nil {
				return false, derr
			}
		}

		key := fmt.Sprintf("dev%d", frame.Record.DeviceID)
		// At LevelReduced and above we can no longer retain full payload
		// semantics, so the accumulator counts frames instead of summing
		// metrics. The mode switch itself is a degradation event.
		if mon.Level() >= resource.LevelReduced {
			st.Accumulator[key]++
		} else {
			st.Accumulator[key] += frame.Record.Metric
		}
		st.ConsumedFrames++
		st.NextSeq = idx + 1
		st.DegradeLevel = mon.Level()

		isCheckpoint := frame.Flags&stream.FlagCheckpoint != 0
		if isCheckpoint {
			st.SeenCheckpoints = append(st.SeenCheckpoints, int64(frame.Record.Seq))
			cp := store.Checkpoint{
				RunID:       cfg.RunID,
				Seq:         int64(frame.Record.Seq),
				FrameOffset: frame.Offset,
				FrameCRC32:  frame.Checksum,
			}
			stateHash, serr := p.st.SaveCheckpoint(cp, st)
			if serr != nil {
				return false, serr
			}
			if _, eerr := p.st.AddEvidence(cfg.RunID, store.EvidenceCheckpoint, []byte(stateHash)); eerr != nil {
				return false, eerr
			}
			if perr := p.st.UpdateProgress(cfg.RunID, store.StateRunning,
				mon.TokensUsed(), mon.BytesUsed(), mon.Level(), cp.Seq); perr != nil {
				return false, perr
			}

			if mon.MustBailout() {
				state = store.StateDegraded
				break
			}
			if cfg.SuspendAfter >= 0 && st.ConsumedFrames >= cfg.SuspendAfter {
				state = store.StateSuspended
				if uerr := p.st.UpdateProgress(cfg.RunID, state,
					mon.TokensUsed(), mon.BytesUsed(), mon.Level(), cp.Seq); uerr != nil {
					return false, uerr
				}
				return true, nil
			}
		}
	}

	if mon.MustBailout() {
		state = store.StateDegraded
	} else if st.NextSeq >= total {
		state = store.StateCompleted
		st.Stage = StageReconciling
	}
	return false, p.st.UpdateProgress(cfg.RunID, state,
		mon.TokensUsed(), mon.BytesUsed(), mon.Level(), st.NextSeq)
}

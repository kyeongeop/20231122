// Package pipeline implements the pausable corpus workflow and its
// pause/resume and final-recomputation comparisons.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"corpusd/internal/corpus"
	"corpusd/internal/model"
	"corpusd/internal/probe"
	"corpusd/internal/store"
)

const (
	deviceAID = "device-a"
	deviceBID = "device-b"
	fixedWork = int64(64 << 10)
)

type Params struct {
	RunID      string
	CorpusDir  string
	Config     model.Config
	PauseAfter int64
}

type Runner struct {
	st *store.Store
	p  Params
}

func New(st *store.Store, p Params) *Runner { return &Runner{st: st, p: p} }

type processState struct {
	firstSeen map[string]int64
	analysis  map[string]map[string]model.Analysis
	degraded  bool
	remaining int64
}

func newState(cfg model.Config) *processState {
	return &processState{
		firstSeen: make(map[string]int64),
		analysis:  make(map[string]map[string]model.Analysis),
		remaining: cfg.MemoryBudgetBytes,
	}
}

func (s *processState) restore(records []model.Record) {
	for _, r := range records {
		if _, ok := s.firstSeen[r.ObjectID]; !ok {
			s.firstSeen[r.ObjectID] = r.Seq
		}
		if s.analysis[r.ObjectID] == nil {
			s.analysis[r.ObjectID] = make(map[string]model.Analysis)
		}
		if !r.Evidence.AnalysisReused {
			s.analysis[r.ObjectID][r.Mode] = r.Analysis
		}
		s.degraded = s.degraded || r.Mode == model.ModeDegraded
		s.remaining = r.Evidence.MemoryRemainingBytes
	}
}

func estimateBytes(size int64) int64 {
	if size > (int64(^uint64(0)>>1)-fixedWork)/3 {
		return int64(^uint64(0) >> 1)
	}
	return size*3 + fixedWork
}

func (r *Runner) processOne(e corpus.Entry, runID string, cfg model.Config, baseNS int64, st *processState) (model.Record, bool, string, error) {
	var rec model.Record
	objectID := model.ObjectID(e.SHA256)
	firstSeq, duplicate := st.firstSeen[objectID]
	firstSeenSeq := firstSeq
	if !duplicate {
		firstSeenSeq = e.Seq
	}

	mode := model.ModeFull
	if st.degraded {
		mode = model.ModeDegraded
	}
	reason := ""
	justDegraded := false
	reused := false
	estimate := estimateBytes(e.Bytes)

	var analysis model.Analysis
	if duplicate {
		if cached, ok := st.analysis[objectID][mode]; ok && cached.ResultSHA256 != "" {
			analysis = cached
			reused = true
		}
	}
	if !reused {
		if !st.degraded {
			switch {
			case cfg.MaxInputBytes > 0 && e.Bytes > cfg.MaxInputBytes:
				mode = model.ModeDegraded
				reason = "input_exceeds_max"
			case estimate > st.remaining:
				mode = model.ModeDegraded
				reason = "memory_budget_exhausted"
			}
			if mode == model.ModeDegraded {
				st.degraded = true
				justDegraded = true
			}
		}
		if mode == model.ModeDegraded {
			if reason == "" {
				reason = "degraded_run"
			}
			analysis = probe.Analyze(nil, e.SHA256, model.ModeDegraded)
		} else {
			data, err := r.readEntry(e)
			if err != nil {
				return rec, false, "", err
			}
			analysis = probe.Analyze(data, e.SHA256, model.ModeFull)
			st.remaining -= estimate
			if st.remaining < 0 {
				st.remaining = 0
			}
		}
	}

	if !duplicate {
		st.firstSeen[objectID] = e.Seq
	}
	if st.analysis[objectID] == nil {
		st.analysis[objectID] = make(map[string]model.Analysis)
	}
	if !reused {
		st.analysis[objectID][mode] = analysis
	}
	if mode == model.ModeDegraded && reason == "" {
		reason = "degraded_run"
	}

	skewNS := cfg.ClockSkewMS * int64(time.Millisecond)
	canonicalNS := baseNS + (e.Seq-1)*cfg.SampleIntervalMS*int64(time.Millisecond)
	observations := []model.ClockObservation{
		{
			DeviceID: deviceAID, ClockRole: "primary",
			RawTSNS: canonicalNS, ClockOffsetNS: 0,
			CorrectedTSNS: canonicalNS, SkewMS: 0,
		},
		{
			DeviceID: deviceBID, ClockRole: "secondary",
			RawTSNS: canonicalNS + skewNS, ClockOffsetNS: skewNS,
			CorrectedTSNS: canonicalNS + skewNS - skewNS,
			SkewMS:        cfg.ClockSkewMS,
		},
	}

	decision := model.DecisionAnalyzed
	if mode == model.ModeDegraded {
		decision = model.DecisionMetadataOnly
	}
	if duplicate {
		if mode == model.ModeDegraded {
			decision = model.DecisionMetadataRepeat
		} else {
			decision = model.DecisionAnalyzedRepeat
		}
	}
	reusedFrom := int64(0)
	if reused {
		reusedFrom = firstSeq
	}
	rec = model.Record{
		Schema:          model.SchemaVersion,
		RecordType:      model.RecordType,
		RunID:           runID,
		Seq:             e.Seq,
		ObjectID:        objectID,
		InputName:       e.Name,
		InputSHA256:     e.SHA256,
		InputBytes:      e.Bytes,
		Observations:    observations,
		CanonicalDevice: deviceAID,
		CanonicalTSNS:   canonicalNS,
		Duplicate:       duplicate,
		DuplicateOfSeq:  firstSeq,
		Mode:            mode,
		DegradedReason:  reason,
		Decision:        decision,
		Analysis:        analysis,
		Evidence: model.Evidence{
			CorpusIndex:          e.Seq,
			SourcePath:           e.Name,
			MemoryBudgetBytes:    cfg.MemoryBudgetBytes,
			MemoryRemainingBytes: st.remaining,
			EstimatedBytes:       estimate,
			ClockCorrectionNS:    skewNS,
			FirstSeenSeq:         firstSeenSeq,
			AnalysisReused:       reused,
			ReusedFromSeq:        reusedFrom,
		},
	}
	return rec, justDegraded, reason, nil
}

func (r *Runner) readEntry(e corpus.Entry) ([]byte, error) {
	f, err := corpus.Open(r.p.CorpusDir, e)
	if err != nil {
		return nil, fmt.Errorf("open corpus %s: %w", e.Name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read corpus %s: %w", e.Name, err)
	}
	if int64(len(data)) != e.Bytes {
		return nil, fmt.Errorf("corpus %s changed size: want %d got %d",
			e.Name, e.Bytes, len(data))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
		return nil, fmt.Errorf("corpus %s changed hash: want %s got %s",
			e.Name, e.SHA256, got)
	}
	return data, nil
}

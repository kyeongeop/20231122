package pipeline

import (
	"fmt"

	"example.com/replay-review/internal/detect"
	"example.com/replay-review/internal/model"
	"example.com/replay-review/internal/store"
)

// Clock abstracts time so runs are deterministic in tests.
type Clock func() int64

// FaultPlan injects deterministic failures for resource-exhaustion drills.
type FaultPlan struct {
	// PauseAfterSegment forces a pause when the next segment id reaches this
	// value, simulating an externally suspended process. Zero disables it.
	PauseAfterSegment int64
	// PauseReason is recorded for the injected pause.
	PauseReason string
}

// SegmentReport summarizes one run segment for the CLI and report builder.
type SegmentReport struct {
	SegmentID int64         `json:"segment_id"`
	Reason    string        `json:"reason"`
	Paused    bool          `json:"paused"`
	Result    detect.Result `json:"result"`
	Degraded  bool          `json:"degraded"`
	NextPos   int           `json:"next_input_pos"`
}

// Pipeline drives replay detection over one input stream and one store.
type Pipeline struct {
	cfg    model.Config
	st     *store.Store
	events []model.Event
	now    Clock
	fault  FaultPlan
}

// New wires a pipeline. The event stream is treated as immutable input.
func New(cfg model.Config, st *store.Store, events []model.Event, now Clock) *Pipeline {
	return &Pipeline{cfg: cfg, st: st, events: events, now: now,
		fault: FaultPlan{PauseReason: model.PauseFaultInjected}}
}

// WithFaultPlan installs deterministic fault injection.
func (p *Pipeline) WithFaultPlan(plan FaultPlan) *Pipeline {
	p.fault = plan
	return p
}

// Run processes at most one segment and returns its report. Call Run again to
// resume; the checkpoint's next_input_pos guarantees no event is skipped or
// processed twice.
func (p *Pipeline) Run() (SegmentReport, error) {
	if err := p.cfg.Validate(); err != nil {
		return SegmentReport{}, err
	}
	hashes, err := store.EventHashes(p.events)
	if err != nil {
		return SegmentReport{}, err
	}
	if err := p.st.IngestEvents(p.events, hashes); err != nil {
		return SegmentReport{}, fmt.Errorf("ingest evidence: %w", err)
	}

	cp, found, err := p.st.LatestCheckpoint()
	if err != nil {
		return SegmentReport{}, err
	}
	var detector *detect.Detector
	var pos int
	var segmentID int64 = 1
	if found {
		if cp.NextInputPos > len(p.events) {
			return SegmentReport{}, fmt.Errorf(
				"checkpoint position %d exceeds input length %d; refusing to resume on a different stream",
				cp.NextInputPos, len(p.events))
		}
		segmentID = cp.SegmentID + 1
		pos = cp.NextInputPos
		detector = detect.Restore(p.cfg, p.st, p.st, cp.Snapshot)
	} else {
		detector = detect.New(p.cfg, p.st, p.st)
	}

	if p.fault.PauseAfterSegment > 0 && segmentID == p.fault.PauseAfterSegment {
		res := detect.Result{Paused: true, Reason: p.fault.PauseReason}
		report := SegmentReport{
			SegmentID: segmentID,
			Reason:    p.fault.PauseReason,
			Paused:    true,
			Result:    res,
			Degraded:  detector.Degraded(),
			NextPos:   pos,
		}
		err := p.persist(segmentID, int64(pos), detector, res,
			"fault injected before processing; intermediate state preserved")
		if err != nil {
			return SegmentReport{}, err
		}
		return report, nil
	}

	res := detector.Process(p.events[pos:])
	nextPos := pos + res.Processed

	// Memory pressure is a soft degradation: the durable finder already backs
	// lookups, so processing continues in this segment but the checkpoint
	// records the condition for reviewers.
	note := "normal processing"
	if detector.Degraded() {
		note = "degraded: issue cache saturated, durable SQLite lookups in use"
	}

	if err := p.persist(segmentID, int64(nextPos), detector, res, note); err != nil {
		return SegmentReport{}, err
	}

	return SegmentReport{
		SegmentID: segmentID,
		Reason:    res.Reason,
		Paused:    res.Paused,
		Result:    res,
		Degraded:  detector.Degraded(),
		NextPos:   nextPos,
	}, nil
}

func (p *Pipeline) persist(segmentID, nextPos int64, detector *detect.Detector,
	res detect.Result, note string) error {
	snap := detector.Snapshot()
	return p.st.RecordSegment(store.Checkpoint{
		SegmentID:    segmentID,
		Reason:       res.Reason,
		Paused:       res.Paused,
		Processed:    res.Processed,
		Degraded:     detector.Degraded(),
		BudgetUsed:   detector.Used(),
		NextInputPos: int(nextPos),
		BatchSize:    p.cfg.BatchSize,
		Snapshot:     snap,
		CreatedAtMs:  p.now(),
	}, res, p.now(), note)
}

// RunToCompletion loops Run until the stream is fully consumed.
func (p *Pipeline) RunToCompletion() ([]SegmentReport, error) {
	var reports []SegmentReport
	for {
		report, err := p.Run()
		if err != nil {
			return reports, err
		}
		reports = append(reports, report)
		if !report.Paused {
			return reports, nil
		}
	}
}

// Remaining reports how many input events the latest checkpoint has not yet
// consumed.
func (p *Pipeline) Remaining() (int, error) {
	cp, found, err := p.st.LatestCheckpoint()
	if err != nil {
		return 0, err
	}
	if !found {
		return len(p.events), nil
	}
	return len(p.events) - cp.NextInputPos, nil
}

package detect

import (
	"fmt"
	"sort"

	"example.com/replay-review/internal/model"
)

// IssueFinder is the durable fallback used when the in-memory issue cache is
// saturated. The store package implements it; the detect package stays free
// of database imports so the logic remains pure and fuzzable.
type IssueFinder interface {
	FindIssue(code, userID string) (model.IssueState, bool, error)
}

// IssueSink persists issue state immediately, used when the memory cache is
// saturated so later consumes can still resolve the issue durably.
type IssueSink interface {
	SaveIssue(iss model.IssueState) error
}

// Detector is the pure, resumable replay-detection state machine.
type Detector struct {
	cfg      model.Config
	issues   map[string]model.IssueState
	lastSeq  map[string]int64
	lastRef  map[string]int64
	lastEvt  map[string]model.Event
	degraded bool
	finder   IssueFinder
	sink     IssueSink
	used     int
}

// New builds a detector with empty per-device tracking state.
func New(cfg model.Config, finder IssueFinder, sink IssueSink) *Detector {
	return &Detector{
		cfg:     cfg,
		issues:  make(map[string]model.IssueState),
		lastSeq: make(map[string]int64),
		lastRef: make(map[string]int64),
		lastEvt: make(map[string]model.Event),
		finder:  finder,
		sink:    sink,
	}
}

// Degraded reports whether memory pressure forced the durable lookup path.
func (d *Detector) Degraded() bool { return d.degraded }

// Used returns the number of events consumed against the segment budget.
func (d *Detector) Used() int { return d.used }

// ResetSegmentBudget restarts the per-segment event counter after a resume.
// Cumulative counters live in the durable checkpoint, not in this counter.
func (d *Detector) ResetSegmentBudget() { d.used = 0 }

// ValidationError records a schema-invalid event without aborting the stream.
type ValidationError struct {
	Sequence int64  `json:"sequence"`
	DeviceID string `json:"device_id"`
	Message  string `json:"message"`
}

// Result is everything one processing segment produced.
type Result struct {
	Decisions []model.Decision  `json:"decisions"`
	Gaps      []model.Gap       `json:"gaps"`
	Errors    []ValidationError `json:"errors"`
	Processed int               `json:"processed"`
	Paused    bool              `json:"paused"`
	Reason    string            `json:"reason"`
}

// Process consumes events in order until the stream ends or a pause condition
// fires. Pause conditions are checked before the event is processed, so the
// same event is never handled twice across resume segments.
func (d *Detector) Process(events []model.Event) Result {
	res := Result{Reason: model.PauseCompleted}
	for idx := range events {
		if d.cfg.MaxEvents > 0 && d.used >= d.cfg.MaxEvents {
			res.Paused = true
			res.Reason = model.PauseBudgetExhausted
			return res
		}
		ev := events[idx]
		if err := ev.Validate(); err != nil {
			res.Errors = append(res.Errors, ValidationError{
				Sequence: ev.Sequence,
				DeviceID: ev.DeviceID,
				Message:  err.Error(),
			})
			d.used++
			continue
		}
		d.detectGaps(ev, &res)
		switch ev.Kind {
		case model.KindIssue:
			d.handleIssue(ev, &res)
		case model.KindConsume:
			d.handleConsume(ev, &res)
		}
		d.used++
		res.Processed++
	}
	return res
}

func (d *Detector) detectGaps(ev model.Event, res *Result) {
	if prev, ok := d.lastSeq[ev.DeviceID]; ok && ev.Sequence > prev+1 {
		res.Gaps = append(res.Gaps, model.Gap{
			Kind:        model.GapSequence,
			DeviceID:    ev.DeviceID,
			AfterSeq:    prev,
			BeforeSeq:   ev.Sequence,
			MissingFrom: prev + 1,
			MissingTo:   ev.Sequence - 1,
			Detail: fmt.Sprintf(
				"device %s missing sequences %d..%d; reference clocks offset_ms=%d",
				ev.DeviceID, prev+1, ev.Sequence-1, ev.OffsetMs),
		})
	}
	d.lastSeq[ev.DeviceID] = ev.Sequence
	d.lastEvt[ev.DeviceID] = ev

	if prevRef, ok := d.lastRef[ev.DeviceID]; ok {
		jump := ev.ReferenceAt() - prevRef
		if jump < 0 {
			jump = -jump
		}
		if jump > d.cfg.ClockGapThresholdMs {
			res.Gaps = append(res.Gaps, model.Gap{
				Kind:      model.GapClock,
				DeviceID:  ev.DeviceID,
				AfterSeq:  ev.Sequence - 1,
				BeforeSeq: ev.Sequence,
				Detail: fmt.Sprintf(
					"device %s reference-clock jump of %dms exceeds threshold %dms",
					ev.DeviceID, jump, d.cfg.ClockGapThresholdMs),
			})
		}
	}
	d.lastRef[ev.DeviceID] = ev.ReferenceAt()
}

func (d *Detector) handleIssue(ev model.Event, res *Result) {
	key := model.IssueKey(ev.Code, ev.UserID)
	if _, exists := d.issues[key]; !exists && len(d.issues) >= d.cfg.MaxTrackedIssues {
		d.degraded = true
		iss := model.IssueState{
			Sequence:    ev.Sequence,
			DeviceID:    ev.DeviceID,
			Code:        ev.Code,
			UserID:      ev.UserID,
			IssuedAtRef: ev.ReferenceAt(),
			WindowMs:    d.cfg.ValidityWindowMs,
		}
		if d.sink != nil {
			// Durable write is the authoritative path; fall through to keep
			// a memory copy so snapshot-only segment boundaries stay correct.
			_ = d.sink.SaveIssue(iss)
		}
	}
	d.issues[key] = model.IssueState{
		Sequence:    ev.Sequence,
		DeviceID:    ev.DeviceID,
		Code:        ev.Code,
		UserID:      ev.UserID,
		IssuedAtRef: ev.ReferenceAt(),
		WindowMs:    d.cfg.ValidityWindowMs,
	}
}

func (d *Detector) handleConsume(ev model.Event, res *Result) {
	key := model.IssueKey(ev.Code, ev.UserID)
	issue, ok := d.issues[key]
	// In degraded mode the durable table is authoritative: issue records beyond
	// the cache limit and all consume updates live there, so consult it first
	// to avoid acting on stale in-memory counters.
	if d.degraded && d.finder != nil {
		if found, hit, err := d.finder.FindIssue(ev.Code, ev.UserID); err == nil && hit {
			issue, ok = found, true
		}
	} else if !ok && d.finder != nil {
		if found, hit, err := d.finder.FindIssue(ev.Code, ev.UserID); err == nil && hit {
			issue, ok = found, true
		}
	}
	dec := model.Decision{
		Sequence: ev.Sequence,
		DeviceID: ev.DeviceID,
		Code:     ev.Code,
		UserID:   ev.UserID,
	}
	if !ok {
		dec.Outcome = model.OutcomeUnknownCode
		dec.Severity = model.SeverityWarning
		dec.Reason = "no issue record for code/user in memory or durable store"
		res.Decisions = append(res.Decisions, dec)
		return
	}
	dec.MatchedIssue = issue.Sequence
	dec.WindowMs = issue.WindowMs
	dec.AgeMs = ev.ReferenceAt() - issue.IssuedAtRef
	switch {
	case dec.AgeMs < 0:
		dec.Outcome = model.OutcomeExpired
		dec.Severity = model.SeverityWarning
		dec.Reason = "clock desync: consume precedes issue on reference clock"
	case dec.AgeMs > issue.WindowMs:
		dec.Outcome = model.OutcomeExpired
		dec.Severity = model.SeverityInfo
		dec.Reason = "code presented after validity window closed"
	case issue.ConsumeCount == 0:
		dec.Outcome = model.OutcomeOK
		dec.Severity = model.SeverityInfo
		dec.Reason = "first consumption inside validity window"
	default:
		dec.Outcome = model.OutcomeReplay
		dec.Severity = model.SeverityCritical
		dec.Reason = fmt.Sprintf(
			"code reused %d time(s); first consume at sequence %d",
			issue.ConsumeCount, issue.FirstConsumeSeq)
	}
	issue.ConsumeCount++
	if issue.FirstConsumeSeq == 0 {
		issue.FirstConsumeSeq = ev.Sequence
	}
	if d.degraded && d.sink != nil {
		_ = d.sink.SaveIssue(issue)
	}
	// Keep the in-memory copy fresh as well: a segment may end on a snapshot
	// boundary before the next durable flush, and the snapshot itself must not
	// carry a stale consume counter.
	d.issues[key] = issue
	res.Decisions = append(res.Decisions, dec)
}

// Snapshot serializes detector state deterministically. Map keys are sorted
// explicitly so reload artifacts keep stable field order across runs.
func (d *Detector) Snapshot() Snapshot {
	keys := make([]string, 0, len(d.issues))
	for k := range d.issues {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	issues := make([]model.IssueState, 0, len(keys))
	for _, k := range keys {
		issues = append(issues, d.issues[k])
	}
	devices := make([]DeviceCursor, 0, len(d.lastSeq))
	for id := range d.lastSeq {
		evt := d.lastEvt[id]
		devices = append(devices, DeviceCursor{
			DeviceID:      id,
			LastSequence:  d.lastSeq[id],
			LastReference: d.lastRef[id],
			LastEvent:     &evt,
		})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].DeviceID < devices[j].DeviceID })
	return Snapshot{
		Issues:   issues,
		Devices:  devices,
		Degraded: d.degraded,
		Used:     d.used,
	}
}

// Restore rehydrates a detector from a previously stored snapshot.
func Restore(cfg model.Config, finder IssueFinder, sink IssueSink, s Snapshot) *Detector {
	d := New(cfg, finder, sink)
	for _, iss := range s.Issues {
		d.issues[model.IssueKey(iss.Code, iss.UserID)] = iss
	}
	for _, cur := range s.Devices {
		d.lastSeq[cur.DeviceID] = cur.LastSequence
		d.lastRef[cur.DeviceID] = cur.LastReference
		if cur.LastEvent != nil {
			d.lastEvt[cur.DeviceID] = *cur.LastEvent
		}
	}
	d.degraded = s.Degraded
	d.used = 0
	return d
}

// DeviceCursor is the per-device resume position.
type DeviceCursor struct {
	DeviceID      string `json:"device_id"`
	LastSequence  int64  `json:"last_sequence"`
	LastReference int64  `json:"last_reference"`
	// LastEvent retains the boundary event of the prior segment so gap
	// detection spans segment boundaries exactly as an uninterrupted run.
	LastEvent *model.Event `json:"last_event,omitempty"`
}

// Snapshot is the serializable detector state embedded in each checkpoint.
type Snapshot struct {
	Issues   []model.IssueState `json:"issues"`
	Devices  []DeviceCursor     `json:"devices"`
	Degraded bool               `json:"degraded"`
	Used     int                `json:"budget_used"`
}

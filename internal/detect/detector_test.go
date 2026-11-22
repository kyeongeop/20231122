package detect

import (
	"testing"

	"example.com/replay-review/internal/model"
)

type memStore struct {
	saved map[string]model.IssueState
}

func newMemStore() *memStore {
	return &memStore{saved: map[string]model.IssueState{}}
}

func (m *memStore) FindIssue(code, userID string) (model.IssueState, bool, error) {
	v, ok := m.saved[model.IssueKey(code, userID)]
	return v, ok, nil
}

func (m *memStore) SaveIssue(iss model.IssueState) error {
	m.saved[model.IssueKey(iss.Code, iss.UserID)] = iss
	return nil
}

// scenario returns the canonical test stream. Device a is on the reference
// clock; device b runs 120s behind and recovers reference time via offset.
// Device a misses its sequence 3 (the missing fragment).
func scenario() []model.Event {
	base := int64(1_700_000_000_000)
	return []model.Event{
		{Sequence: 1, DeviceID: "a", Code: "C1", UserID: "u", Kind: model.KindIssue, ObservedAt: base},
		{Sequence: 2, DeviceID: "a", Code: "C2", UserID: "u", Kind: model.KindIssue, ObservedAt: base + 40000},
		{Sequence: 2, DeviceID: "b", Code: "C1", UserID: "u", Kind: model.KindConsume,
			ObservedAt: base + 30000 - 120000, OffsetMs: 120000},
		// Device a sequence 3 is absent.
		{Sequence: 4, DeviceID: "a", Code: "C1", UserID: "u", Kind: model.KindConsume, ObservedAt: base + 60000},
		{Sequence: 5, DeviceID: "a", Code: "C2", UserID: "u", Kind: model.KindConsume, ObservedAt: base + 400000},
		{Sequence: 4, DeviceID: "b", Code: "C3", UserID: "u", Kind: model.KindConsume, ObservedAt: base + 100000},
	}
}

func TestReplayExpiryAndUnknown(t *testing.T) {
	d := New(model.DefaultConfig(), newMemStore(), newMemStore())
	res := d.Process(scenario())
	if res.Processed != 6 {
		t.Fatalf("processed = %d, want 6", res.Processed)
	}
	want := []struct {
		device  string
		outcome string
	}{
		{"b", model.OutcomeOK},
		{"a", model.OutcomeReplay},
		{"a", model.OutcomeExpired},
		{"b", model.OutcomeUnknownCode},
	}
	if len(res.Decisions) != len(want) {
		t.Fatalf("decisions = %d, want %d", len(res.Decisions), len(want))
	}
	for i, w := range want {
		got := res.Decisions[i]
		if got.DeviceID != w.device || got.Outcome != w.outcome {
			t.Fatalf("decision %d = (%s, %s), want (%s, %s)",
				i, got.DeviceID, got.Outcome, w.device, w.outcome)
		}
	}
	if res.Decisions[1].Severity != model.SeverityCritical {
		t.Fatalf("replay severity = %s, want critical", res.Decisions[1].Severity)
	}
}

func TestGapsTrackMissingFragmentAndClockJump(t *testing.T) {
	cfg := model.DefaultConfig()
	cfg.ClockGapThresholdMs = 1000
	d := New(cfg, newMemStore(), newMemStore())
	res := d.Process(scenario())

	var seqGaps, clockGaps int
	for _, g := range res.Gaps {
		switch g.Kind {
		case model.GapSequence:
			seqGaps++
			if g.MissingFrom != 3 || g.MissingTo != 3 {
				t.Fatalf("unexpected sequence gap: %+v", g)
			}
		case model.GapClock:
			clockGaps++
		}
	}
	if seqGaps != 2 {
		t.Fatalf("sequence gaps = %d, want 2 (one per device)", seqGaps)
	}
	if clockGaps == 0 {
		t.Fatal("expected clock-gap evidence")
	}
}

func TestBudgetPauseAndResumeIsEquivalent(t *testing.T) {
	events := scenario()
	cfg := model.DefaultConfig()
	cfg.MaxEvents = 2
	ms := newMemStore()
	d := New(cfg, ms, ms)

	first := d.Process(events)
	if !first.Paused || first.Reason != model.PauseBudgetExhausted || first.Processed != 2 {
		t.Fatalf("first segment = %+v", first)
	}
	snap := d.Snapshot()

	resumed := Restore(cfg, ms, ms, snap)
	if resumed.Used() != 0 {
		t.Fatalf("resumed budget counter = %d, want 0", resumed.Used())
	}
	second := resumed.Process(events[2:])
	if second.Processed != 2 || !second.Paused {
		t.Fatalf("second segment = %+v", second)
	}
	third := Restore(cfg, ms, ms, resumed.Snapshot()).Process(events[4:])
	if third.Paused || third.Processed != 2 {
		t.Fatalf("third segment = %+v", third)
	}

	oneShot := New(model.DefaultConfig(), newMemStore(), newMemStore()).Process(events)
	segmented := append(append(append([]model.Decision{},
		first.Decisions...), second.Decisions...), third.Decisions...)
	if !decisionsEqual(segmented, oneShot.Decisions) {
		t.Fatalf("segmented %+v != one-shot %+v", segmented, oneShot.Decisions)
	}
	mergedGaps := append(append(append([]model.Gap{},
		first.Gaps...), second.Gaps...), third.Gaps...)
	if len(mergedGaps) != len(oneShot.Gaps) {
		t.Fatalf("gap count segmented=%d one-shot=%d", len(mergedGaps), len(oneShot.Gaps))
	}
	for _, cur := range Restore(cfg, ms, ms, resumed.Snapshot()).Snapshot().Devices {
		if cur.LastEvent == nil {
			t.Fatalf("device %s snapshot missing boundary event", cur.DeviceID)
		}
	}
}

func TestDegradedDurablePathMatchesInMemory(t *testing.T) {
	events := scenario()
	baseline := New(model.DefaultConfig(), newMemStore(), newMemStore()).Process(events)

	cfg := model.DefaultConfig()
	cfg.MaxTrackedIssues = 1
	ms := newMemStore()
	detector := New(cfg, ms, ms)
	degraded := detector.Process(events)

	if !detector.Degraded() {
		t.Fatal("detector did not enter degraded mode")
	}
	if !decisionsEqual(degraded.Decisions, baseline.Decisions) {
		t.Fatalf("degraded %+v != baseline %+v", degraded.Decisions, baseline.Decisions)
	}
	if len(ms.saved) == 0 {
		t.Fatal("durable store received no issue rows")
	}
}

func TestDegradedReplaySurvivesSegmentBoundary(t *testing.T) {
	cfg := model.DefaultConfig()
	cfg.MaxTrackedIssues = 1
	cfg.MaxEvents = 2
	events := scenario()
	ms := newMemStore()
	d := New(cfg, ms, ms)

	first := d.Process(events)
	if !first.Paused {
		t.Fatal("expected budget pause")
	}
	snap := d.Snapshot()

	// Resume from the JSON-style snapshot and drain the stream.
	resumed := Restore(cfg, ms, ms, snap)
	var all []model.Decision
	all = append(all, first.Decisions...)
	pos := first.Processed
	for pos < len(events) {
		part := resumed.Process(events[pos:])
		all = append(all, part.Decisions...)
		pos += part.Processed
		if !part.Paused {
			break
		}
		resumed = Restore(cfg, ms, ms, resumed.Snapshot())
	}

	var replays int
	for _, dec := range all {
		if dec.Outcome == model.OutcomeReplay {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("replays across degraded segments = %d, want 1", replays)
	}
}

func TestValidationErrorsArePreserved(t *testing.T) {
	d := New(model.DefaultConfig(), newMemStore(), newMemStore())
	events := append(scenario(), model.Event{
		Sequence: 99, DeviceID: "a", Code: "", UserID: "u",
		Kind: model.KindConsume, ObservedAt: 1,
	})
	res := d.Process(events)
	if len(res.Errors) != 1 || res.Processed != 6 {
		t.Fatalf("errors=%d processed=%d", len(res.Errors), res.Processed)
	}
}

func TestNegativeAgeClockDesync(t *testing.T) {
	base := int64(1_700_000_000_000)
	d := New(model.DefaultConfig(), newMemStore(), newMemStore())
	first := d.Process([]model.Event{
		{Sequence: 1, DeviceID: "a", Code: "C", UserID: "u", Kind: model.KindConsume, ObservedAt: base},
	})
	if first.Decisions[0].Outcome != model.OutcomeUnknownCode {
		t.Fatalf("pre-issue consume = %s", first.Decisions[0].Outcome)
	}
	// Issue arrives later but its reference time is after the consume.
	d.Process([]model.Event{
		{Sequence: 2, DeviceID: "b", Code: "C", UserID: "u", Kind: model.KindIssue,
			ObservedAt: base + 1000 - 5000, OffsetMs: 5000},
	})
	second := d.Process([]model.Event{
		{Sequence: 3, DeviceID: "a", Code: "C", UserID: "u", Kind: model.KindConsume, ObservedAt: base},
	})
	if second.Decisions[0].Outcome != model.OutcomeExpired || second.Decisions[0].AgeMs >= 0 {
		t.Fatalf("negative-age case = %+v", second.Decisions[0])
	}
}

func decisionsEqual(a, b []model.Decision) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Sequence != b[i].Sequence ||
			a[i].DeviceID != b[i].DeviceID ||
			a[i].Outcome != b[i].Outcome ||
			a[i].Severity != b[i].Severity ||
			a[i].Reason != b[i].Reason {
			return false
		}
	}
	return true
}

package detect

import (
	"encoding/json"
	"testing"

	"example.com/replay-review/internal/model"
)

// TestSnapshotJSONRoundTrip mirrors the libFuzzer invariant: a detector
// restored from its JSON snapshot must continue processing identically to an
// uninterrupted detector over the same stream.
func TestSnapshotJSONRoundTrip(t *testing.T) {
	cfg := model.DefaultConfig()
	events := scenario()
	split := 3

	oneShot := New(cfg, newMemStore(), newMemStore()).Process(events)

	firstDetector := New(cfg, newMemStore(), newMemStore())
	first := firstDetector.Process(events[:split])
	raw, err := json.Marshal(firstDetector.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	second := Restore(cfg, newMemStore(), newMemStore(), snap).Process(events[split:])

	combined := append(append([]model.Decision{}, first.Decisions...), second.Decisions...)
	if !decisionsEqual(combined, oneShot.Decisions) {
		t.Fatalf("snapshot round-trip diverged:\ncombined=%+v\none-shot=%+v",
			combined, oneShot.Decisions)
	}
}

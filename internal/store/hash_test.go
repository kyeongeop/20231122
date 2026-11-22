package store

import (
	"testing"

	"example.com/replay-review/internal/model"
)

func TestEventHashStableAndOrderSensitive(t *testing.T) {
	ev := model.Event{
		Sequence: 1, DeviceID: "dev-a", Code: "C-1", UserID: "u1",
		Kind: model.KindIssue, ObservedAt: 1000, OffsetMs: 5,
	}
	h1, err := EventHash(ev)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := EventHash(ev)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash unstable or wrong length: %s %s", h1, h2)
	}

	mutated := ev
	mutated.OffsetMs = 6
	h3, err := EventHash(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("hash did not change when a field changed")
	}
}

func TestSQLiteRoundTrip(t *testing.T) {
	st, err := Open(t.TempDir() + "/evidence.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	events := []model.Event{
		{Sequence: 1, DeviceID: "a", Code: "C1", UserID: "u",
			Kind: model.KindIssue, ObservedAt: 100},
		{Sequence: 2, DeviceID: "a", Code: "C1", UserID: "u",
			Kind: model.KindConsume, ObservedAt: 200},
	}
	hashes, err := EventHashes(events)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.IngestEvents(events, hashes); err != nil {
		t.Fatal(err)
	}
	// Re-ingestion is idempotent and must not duplicate evidence.
	if err := st.IngestEvents(events, hashes); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.LoadEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d events, want 2", len(loaded))
	}
	if loaded[0].RawSHA256 != hashes[0] {
		t.Fatal("evidence hash did not survive round-trip")
	}

	iss := model.IssueState{
		Sequence: 1, DeviceID: "a", Code: "C1", UserID: "u",
		IssuedAtRef: 100, WindowMs: 300000,
	}
	if err := st.SaveIssue(iss); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.FindIssue("C1", "u")
	if err != nil || !ok {
		t.Fatalf("FindIssue ok=%v err=%v", ok, err)
	}
	if got.IssuedAtRef != 100 || got.WindowMs != 300000 {
		t.Fatalf("issue round-trip mismatch: %+v", got)
	}
}

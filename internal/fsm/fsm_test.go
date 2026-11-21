package fsm

import "testing"

func run(events []Event) *Machine {
	m := NewMachine()
	for _, ev := range events {
		m.Step(Input{Event: ev})
	}
	return m
}

func TestRecoveryHappyPath(t *testing.T) {
	m := run([]Event{
		{Seq: 1, Kind: "CONNECT"},
		{Seq: 2, Kind: "SUBMIT", MsgID: "m-100"},
		{Seq: 3, Kind: "TIMEOUT"},
		{Seq: 4, Kind: "RECOVER"},
		{Seq: 5, Kind: "ACK", MsgID: "m-100"},
	})
	if got := m.Snapshot().State; got != StateAcked {
		t.Fatalf("state = %s, want ACKED", got)
	}
}

func TestUnknownExtensionDoesNotMutateState(t *testing.T) {
	before := NewMachine()
	before.Step(Input{Event: Event{Seq: 1, Kind: "CONNECT"}})
	beforeHash := before.Snapshot().Hash()

	after := NewMachine()
	after.Step(Input{Event: Event{Seq: 1, Kind: "CONNECT"}})
	out, _ := after.Step(Input{Event: Event{Seq: 2, Kind: "X_PING", MsgID: "x"}})

	if out.Accepted {
		t.Fatal("unknown extension must be rejected")
	}
	if after.Snapshot().State != StateConnected {
		t.Fatalf("state mutated to %s", after.Snapshot().State)
	}
	if after.Snapshot().Hash() == beforeHash {
		t.Fatal("unknown counter should change hash even if protocol state is stable")
	}
	if after.Snapshot().UnknownSeen != 1 {
		t.Fatalf("unknown seen = %d, want 1", after.Snapshot().UnknownSeen)
	}
}

func TestReorderIsRejected(t *testing.T) {
	m := NewMachine()
	m.Step(Input{Event: Event{Seq: 1, Kind: "CONNECT"}})
	m.Step(Input{Event: Event{Seq: 3, Kind: "TIMEOUT"}}) // stale-ish but seq grows; invalid in CONNECTED
	out, _ := m.Step(Input{Event: Event{Seq: 2, Kind: "SUBMIT", MsgID: "m"}})
	if out.Accepted || out.Reason == "" {
		t.Fatalf("reordered lower seq must be rejected, got %+v", out)
	}
	if m.Snapshot().State != StateConnected {
		t.Fatalf("state = %s, want still CONNECTED", m.Snapshot().State)
	}
}

func TestDuplicateSubmitIsIdempotent(t *testing.T) {
	m := NewMachine()
	m.Step(Input{Event: Event{Seq: 1, Kind: "CONNECT"}})
	first, _ := m.Step(Input{Event: Event{Seq: 2, Kind: "SUBMIT", MsgID: "m-300"}})
	second, _ := m.Step(Input{Event: Event{Seq: 3, Kind: "SUBMIT", MsgID: "m-300"}})
	if !first.Accepted {
		t.Fatal("first submit must be accepted")
	}
	if !second.Duplicate || second.Accepted {
		t.Fatalf("second submit must be a duplicate no-op, got %+v", second)
	}
	if m.Snapshot().Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", m.Snapshot().Attempts)
	}
}

func TestDeterministicHashAcrossInstances(t *testing.T) {
	events := []Event{
		{Seq: 1, Kind: "CONNECT"},
		{Seq: 2, Kind: "SUBMIT", MsgID: "m"},
		{Seq: 3, Kind: "TIMEOUT"},
		{Seq: 4, Kind: "RECOVER"},
		{Seq: 5, Kind: "ACK", MsgID: "m"},
	}
	h1 := run(events).Snapshot().Hash()
	h2 := run(events).Snapshot().Hash()
	if h1 != h2 {
		t.Fatalf("nondeterministic hash: %s != %s", h1, h2)
	}
}

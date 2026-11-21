package fsm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

var kinds = []string{
	"CONNECT", "SUBMIT", "ACK", "TIMEOUT", "RETRY", "RECOVER", "CLOSE",
	"X_PING", "X_BOGUS", // unknown extensions act as the fuzzed control input
}

// decodeEvents turns fuzz bytes into a bounded, monotonically sequenced event
// stream. Decoding is purely structural so the corpus can freely explore the
// transition table, including unknown extensions and duplicates.
func decodeEvents(b []byte) []Event {
	if len(b) < 2 {
		return nil
	}
	n := int(b[0])%16 + 1
	events := make([]Event, 0, n)
	pos := 1
	var seq int64
	for i := 0; i < n && pos+2 <= len(b); i++ {
		kind := kinds[int(b[pos])%len(kinds)]
		pos++
		var idByte byte
		if pos < len(b) {
			idByte = b[pos]
			pos++
		}
		// A small id space deliberately creates frequent duplicate msg ids.
		msgID := ""
		if kind == "SUBMIT" || kind == "ACK" {
			msgID = fmt.Sprintf("m-%d", int(idByte)%4)
		}
		// Occasionally reuse an older seq to exercise the stale-seq guard.
		if idByte%7 == 0 && seq > 1 {
			seq--
		} else {
			seq++
		}
		events = append(events, Event{Seq: seq, Kind: kind, MsgID: msgID})
	}
	return events
}

// FuzzMachine is the libFuzzer-compatible entry point run by `go test -fuzz`.
// It asserts three invariants on every input:
//  1. the machine never panics,
//  2. replaying the same stream on a fresh machine yields identical hashes,
//  3. an unknown extension never leaves the machine in an undefined state.
func FuzzMachine(f *testing.F) {
	seeds := [][]byte{
		{6, 0, 0, 1, 1, 3, 0, 5, 0, 2, 1, 6, 0},
		{5, 0, 0, 1, 1, 3, 0, 7, 9, 2, 1},
		{4, 0, 0, 1, 1, 1, 1, 2, 2},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		events := decodeEvents(b)
		if len(events) == 0 {
			return
		}

		first := run(events)
		second := run(events)
		if first.Snapshot().Hash() != second.Snapshot().Hash() {
			t.Fatalf("nondeterministic replay: %x", b)
		}

		// Final state must always be one of the defined states.
		switch first.Snapshot().State {
		case StateInit, StateConnected, StateRequestSent, StateAcked,
			StateTimedOut, StateRecovering, StateClosed:
		default:
			t.Fatalf("undefined state reached: %q from %x", first.Snapshot().State, b)
		}

		// Rejected/unknown counts must stay non-negative and bounded by steps.
		snap := first.Snapshot()
		if snap.Rejected < 0 || snap.UnknownSeen < 0 ||
			snap.Rejected+snap.UnknownSeen > len(events)*2 {
			t.Fatalf("counter invariant broken: %+v", snap)
		}
	})
}

func TestDecodeEventsRoundTrip(t *testing.T) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, 0x0701010006)
	ev := decodeEvents(b)
	if len(ev) == 0 {
		t.Fatal("expected decoded events")
	}
}

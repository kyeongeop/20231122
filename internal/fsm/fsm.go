package fsm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// State is a single node of the protocol timeout state machine.
type State string

const (
	StateInit        State = "INIT"
	StateConnected   State = "CONNECTED"
	StateRequestSent State = "REQUEST_SENT"
	StateAcked       State = "ACKED"
	StateTimedOut    State = "TIMED_OUT"
	StateRecovering  State = "RECOVERING"
	StateClosed      State = "CLOSED"
)

// Event is a protocol input. Unknown event kinds are kept verbatim so that an
// unknown extension can be replayed as a control sample.
type Event struct {
	Seq   int64  `json:"seq"`
	Kind  string `json:"kind"`
	MsgID string `json:"msg_id"`
}

// Input is one recorded step fed to the machine.
type Input struct {
	Event Event `json:"event"`
}

// Outcome records how the machine reacted to one input.
type Outcome struct {
	Accepted  bool   `json:"accepted"`
	Reason    string `json:"reason"`
	Duplicate bool   `json:"duplicate"`
}

// Snapshot is the fully determined state after applying an input.
type Snapshot struct {
	State       State  `json:"state"`
	LastSeq     int64  `json:"last_seq"`
	InFlight    string `json:"in_flight"`
	AckedMsg    string `json:"acked_msg"`
	Attempts    int    `json:"attempts"`
	Retries     int    `json:"retries"`
	Rejected    int    `json:"rejected"`
	UnknownSeen int    `json:"unknown_seen"`
	SeenMsg     string `json:"seen_msg"`
}

// Hash returns a deterministic content hash of the snapshot. Equal hashes imply
// equal states, which is what replay determinism is checked against.
func (s Snapshot) Hash() string {
	raw := fmt.Sprintf("%s|%d|%s|%s|%d|%d|%d|%d|%s",
		s.State, s.LastSeq, s.InFlight, s.AckedMsg,
		s.Attempts, s.Retries, s.Rejected, s.UnknownSeen, s.SeenMsg)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Machine is the protocol timeout state machine. It is deterministic: the same
// ordered input stream always produces the same snapshots and hashes.
type Machine struct {
	snap Snapshot
	seen map[string]struct{}
}

// NewMachine starts from the INIT state.
func NewMachine() *Machine {
	return &Machine{
		snap: Snapshot{State: StateInit},
		seen: map[string]struct{}{},
	}
}

// Snapshot returns a copy of the current state.
func (m *Machine) Snapshot() Snapshot { return m.snap }

// Step applies one input and returns the resulting outcome and snapshot.
func (m *Machine) Step(in Input) (Outcome, Snapshot) {
	ev := in.Event
	out := Outcome{}

	// Monotonic sequence validation: reordered or stale inputs are rejected.
	if ev.Seq <= m.snap.LastSeq {
		out.Reason = fmt.Sprintf("stale seq %d <= last %d", ev.Seq, m.snap.LastSeq)
		m.snap.Rejected++
		return out, m.snap
	}

	// Duplicate submission: a resubmitted message id is idempotently ignored.
	// Only SUBMIT participates; an ACK carrying the same id is a server response
	// and must still be processed rather than treated as a duplicate.
	if ev.Kind == "SUBMIT" && ev.MsgID != "" {
		if _, dup := m.seen[ev.MsgID]; dup {
			out.Duplicate = true
			out.Reason = "duplicate message id: idempotent no-op"
			m.snap.LastSeq = ev.Seq
			return out, m.snap
		}
	}

	accepted, reason := m.transition(ev)
	out.Accepted = accepted
	out.Reason = reason
	m.snap.LastSeq = ev.Seq
	if !accepted {
		m.snap.Rejected++
	}
	if ev.MsgID != "" && accepted {
		m.seen[ev.MsgID] = struct{}{}
		m.snap.SeenMsg = ev.MsgID
	}
	return out, m.snap
}

func (m *Machine) transition(ev Event) (bool, string) {
	switch ev.Kind {
	case "CONNECT":
		if m.snap.State != StateInit {
			return false, "CONNECT only valid in INIT"
		}
		m.snap.State = StateConnected
		return true, "connected"

	case "SUBMIT":
		if m.snap.State != StateConnected && m.snap.State != StateTimedOut {
			return false, "SUBMIT only valid in CONNECTED or TIMED_OUT"
		}
		m.snap.State = StateRequestSent
		m.snap.InFlight = ev.MsgID
		m.snap.Attempts++
		return true, "request sent"

	case "ACK":
		if m.snap.State != StateRequestSent && m.snap.State != StateRecovering {
			return false, "ACK only valid in REQUEST_SENT or RECOVERING"
		}
		m.snap.State = StateAcked
		m.snap.AckedMsg = ev.MsgID
		m.snap.InFlight = ""
		return true, "acknowledged"

	case "TIMEOUT":
		if m.snap.State != StateRequestSent {
			return false, "TIMEOUT only valid in REQUEST_SENT"
		}
		m.snap.State = StateTimedOut
		m.snap.Retries++
		return true, "timed out"

	case "RETRY":
		if m.snap.State != StateTimedOut {
			return false, "RETRY only valid in TIMED_OUT"
		}
		m.snap.State = StateRequestSent
		m.snap.Attempts++
		return true, "retry scheduled"

	case "RECOVER":
		if m.snap.State != StateTimedOut {
			return false, "RECOVER only valid in TIMED_OUT"
		}
		m.snap.State = StateRecovering
		return true, "recovery started"

	case "CLOSE":
		if m.snap.State == StateInit || m.snap.State == StateClosed {
			return false, "CLOSE not valid in INIT/CLOSED"
		}
		m.snap.State = StateClosed
		return true, "closed"

	default:
		// Unknown extension: explicitly rejected, never mutates protocol state.
		m.snap.UnknownSeen++
		return false, "unknown extension: " + ev.Kind
	}
}

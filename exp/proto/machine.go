package proto

import "fmt"

// State is the protocol state machine state.
type State int

const (
	StateIdle State = iota
	StateHello
	StateAuth
	StateOpen
	StateClosed
	StateError
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateHello:
		return "HELLO"
	case StateAuth:
		return "AUTH"
	case StateOpen:
		return "OPEN"
	case StateClosed:
		return "CLOSED"
	case StateError:
		return "ERROR"
	}
	return "UNKNOWN"
}

// Machine is a session protocol state machine. Version selects the
// implementation snapshot: 1 = v1 (buggy), 2 = v2 (fixed).
type Machine struct {
	Version int
	State   State
	buf     []byte // session buffer, allocated only on OPEN
	authed  bool
}

func New(version int) *Machine {
	return &Machine{Version: version, State: StateIdle}
}

// Step applies one command and returns a result string.
// v1 contains a deliberate bug: SEND before OPEN dereferences the
// session buffer that is only allocated in OPEN, causing a panic.
// v1 also accepts CLOSE from any state; v2 rejects it.
func (m *Machine) Step(c Command) (result string) {
	switch c.Op {
	case OpNop:
		return "NOP"
	case OpHello:
		if m.State != StateIdle {
			return "ERR_STATE"
		}
		m.State = StateHello
		return "OK_HELLO"
	case OpAuth:
		if m.State != StateHello {
			return "ERR_STATE"
		}
		if len(c.Payload) == 0 {
			m.State = StateError
			return "ERR_EMPTY_TOKEN"
		}
		m.authed = true
		m.State = StateAuth
		return "OK_AUTH"
	case OpOpen:
		if m.State != StateAuth || !m.authed {
			return "ERR_STATE"
		}
		m.buf = make([]byte, 64)
		m.State = StateOpen
		return "OK_OPEN"
	case OpSend:
		if m.Version == 1 {
			// BUG(v1): no state check; buf is nil unless OPEN happened.
			m.buf[0] = byte(len(c.Payload))
			return "OK_SEND"
		}
		if m.State != StateOpen {
			return "ERR_STATE"
		}
		m.buf[0] = byte(len(c.Payload))
		return "OK_SEND"
	case OpClose:
		if m.Version == 1 {
			// BUG(v1): CLOSE accepted from any state.
			m.State = StateClosed
			return "OK_CLOSE"
		}
		if m.State != StateOpen && m.State != StateAuth {
			return "ERR_STATE"
		}
		m.State = StateClosed
		return "OK_CLOSE"
	}
	return fmt.Sprintf("ERR_UNKNOWN_OP_%d", byte(c.Op))
}

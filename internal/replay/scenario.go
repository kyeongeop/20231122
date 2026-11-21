package replay

import "timeoutfsm/internal/fsm"

// Scenario is a named, ordered input stream with a human description.
type Scenario struct {
	Name   string
	Desc   string
	Events []fsm.Event
}

// BaselineRecovery drives the machine through timeout -> recover -> ACK, then
// closes. It is the stream that gets journaled and later replayed once.
func BaselineRecovery() Scenario {
	return Scenario{
		Name: "baseline_recovery",
		Desc: "CONNECT -> SUBMIT -> TIMEOUT -> RECOVER -> ACK -> CLOSE",
		Events: []fsm.Event{
			{Seq: 1, Kind: "CONNECT", MsgID: ""},
			{Seq: 2, Kind: "SUBMIT", MsgID: "m-100"},
			{Seq: 3, Kind: "TIMEOUT", MsgID: ""},
			{Seq: 4, Kind: "RECOVER", MsgID: ""},
			{Seq: 5, Kind: "ACK", MsgID: "m-100"},
			{Seq: 6, Kind: "CLOSE", MsgID: ""},
		},
	}
}

// UnknownExtensionControl inserts an unknown extension into an otherwise valid
// recovery flow. The machine must reject it without changing protocol state.
func UnknownExtensionControl() Scenario {
	return Scenario{
		Name: "unknown_extension_control",
		Desc: "valid recovery with unknown extension X_PING injected before ACK",
		Events: []fsm.Event{
			{Seq: 1, Kind: "CONNECT", MsgID: ""},
			{Seq: 2, Kind: "SUBMIT", MsgID: "m-200"},
			{Seq: 3, Kind: "TIMEOUT", MsgID: ""},
			{Seq: 4, Kind: "RECOVER", MsgID: ""},
			{Seq: 5, Kind: "X_PING", MsgID: "ext-1"},
			{Seq: 6, Kind: "ACK", MsgID: "m-200"},
			{Seq: 7, Kind: "CLOSE", MsgID: ""},
		},
	}
}

// ReorderCheck delivers inputs out of order (a higher seq before a lower one)
// to prove stale inputs are rejected and state stays consistent.
func ReorderCheck() Scenario {
	base := BaselineRecovery().Events
	// Swap TIMEOUT(seq3) and SUBMIT(seq2): TIMEOUT arrives first and must be
	// rejected because the machine is still in CONNECTED.
	swapped := make([]fsm.Event, len(base))
	copy(swapped, base)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	return Scenario{
		Name:   "reorder_check",
		Desc:   "TIMEOUT(seq3) delivered before SUBMIT(seq2); state guard and stale-seq guard both reject the inversion",
		Events: swapped,
	}
}

// DuplicateSubmit resends the same message id to verify idempotent handling.
func DuplicateSubmit() Scenario {
	return Scenario{
		Name: "duplicate_submit",
		Desc: "same msg_id submitted twice; second occurrence is a duplicate no-op",
		Events: []fsm.Event{
			{Seq: 1, Kind: "CONNECT", MsgID: ""},
			{Seq: 2, Kind: "SUBMIT", MsgID: "m-300"},
			{Seq: 3, Kind: "SUBMIT", MsgID: "m-300"},
			{Seq: 4, Kind: "ACK", MsgID: "m-300b"},
			{Seq: 5, Kind: "CLOSE", MsgID: ""},
		},
	}
}

// AllScenarios returns every scenario in execution order.
func AllScenarios() []Scenario {
	return []Scenario{
		BaselineRecovery(),
		UnknownExtensionControl(),
		ReorderCheck(),
		DuplicateSubmit(),
	}
}

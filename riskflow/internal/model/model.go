// Package model defines the domain vocabulary of the dependency-version risk
// review pipeline: wire formats, lifecycle states, roles and evidence rows.
package model

import "time"

// Schema generations understood by the pipeline.
const (
	SchemaV1 = "v1" // legacy flat JSON-Lines, no envelope/checksum
	SchemaV2 = "v2" // framed envelope with per-record checksum and framing
)

// Lifecycle states. Ordering matters: StateRank lets the report identify the
// FIRST erroneous state instead of merely returning an aggregate score.
const (
	StateReceived  = "RECEIVED"
	StateParsed    = "PARSED"
	StateTruncated = "TRUNCATED"
	StateRecovered = "RECOVERED"
	StateChecked   = "PERMISSION_CHECKED"
	StateRisked    = "RISK_SCORED"
	StateBlocked   = "BLOCKED"
	StateAccepted  = "ACCEPTED"
	StateRejected  = "REJECTED"
)

// StateRank is the canonical evaluation order used for first-error detection.
var StateRank = []string{
	StateReceived,
	StateParsed,
	StateTruncated,
	StateRecovered,
	StateChecked,
	StateRisked,
	StateBlocked,
	StateAccepted,
	StateRejected,
}

// Terminal/error states and the helper rank table.
var stateRankIndex = func() map[string]int {
	m := make(map[string]int, len(StateRank))
	for i, s := range StateRank {
		m[s] = i
	}
	return m
}()

// RankOf returns the ordinal position of a state and whether it is known.
func RankOf(state string) (int, bool) {
	r, ok := stateRankIndex[state]
	return r, ok
}

// IsErrorState reports whether a state represents a failure condition.
func IsErrorState(state string) bool {
	switch state {
	case StateTruncated, StateBlocked, StateRejected:
		return true
	default:
		return false
	}
}

// Roles participating in the permission decision.
const (
	RoleReviewer = "reviewer"
	RoleApprover = "approver"
	RoleCI       = "ci-bot"
	RoleGuest    = "guest"
)

// Decision values carried on each record.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Record is the normalized, format-independent dependency risk record.
type Record struct {
	RecordID  string `json:"record_id"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Severity  string `json:"severity"` // low|medium|high|critical
	Decision  string `json:"decision"` // allow|deny
	Role      string `json:"role"`     // role requesting the decision
	InputHash string `json:"input_hash"`
	Checksum  string `json:"checksum,omitempty"` // v2 only
	Schema    string `json:"schema"`
	Raw       string `json:"-"` // original wire bytes, retained as evidence
}

// Envelope is the v2 outer frame (length-prefixed JSON object per record).
type Envelope struct {
	Schema   string `json:"schema"`
	BatchID  string `json:"batch_id"`
	Checksum string `json:"checksum"`
	Payload  Record `json:"payload"`
}

// Transition is one append-only state-machine step, persisted as evidence.
type Transition struct {
	ID          int64
	RecordID    string
	Seq         int
	FromState   string
	ToState     string
	Actor       string
	Permit      bool
	Granted     bool
	Reason      string
	AttackInput string
	TriggerSite string
	InputHash   string
	EventTime   time.Time
}

// FirstError pins the earliest failing state for a record, with the evidence
// needed to re-verify it during replay.
type FirstError struct {
	RecordID  string `json:"record_id"`
	State     string `json:"state"`
	Seq       int    `json:"seq"`
	Reason    string `json:"reason"`
	InputHash string `json:"input_hash"`
}

// ReplayReport is the deterministic output of one replay run.
type ReplayReport struct {
	BatchID     string       `json:"batch_id"`
	Records     int          `json:"records"`
	Transitions int          `json:"transitions"`
	Recovered   int          `json:"recovered_records"`
	FirstErrors []FirstError `json:"first_errors"`
	ReplayedOK  bool         `json:"replayed_ok"`
	EvidenceDB  string       `json:"evidence_db"`
}

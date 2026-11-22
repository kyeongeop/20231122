package model

// Outcome labels produced by the detector.
const (
	OutcomeOK          = "ok"           // first legitimate consumption within the window
	OutcomeReplay      = "replay"       // code reused while still inside its validity window
	OutcomeExpired     = "expired"      // code presented after its validity window closed
	OutcomeUnknownCode = "unknown_code" // no matching issue record exists yet
)

// Severity levels, ordered from least to most severe.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Gap kinds recorded when the input stream is not contiguous.
const (
	GapSequence = "sequence_gap" // missing sequence numbers between adjacent records
	GapClock    = "clock_gap"    // reference-clock jump beyond the configured threshold
)

// Decision is the deterministic verdict for one consume event.
type Decision struct {
	Sequence     int64  `json:"sequence"`
	DeviceID     string `json:"device_id"`
	Code         string `json:"code"`
	UserID       string `json:"user_id"`
	Outcome      string `json:"outcome"`
	Severity     string `json:"severity"`
	Reason       string `json:"reason"`
	MatchedIssue int64  `json:"matched_issue_sequence"`
	AgeMs        int64  `json:"age_ms"`
	WindowMs     int64  `json:"window_ms"`
}

// Gap documents a missing fragment of the input stream.
type Gap struct {
	Kind        string `json:"kind"`
	DeviceID    string `json:"device_id"`
	AfterSeq    int64  `json:"after_sequence"`
	BeforeSeq   int64  `json:"before_sequence"`
	MissingFrom int64  `json:"missing_from"`
	MissingTo   int64  `json:"missing_to"`
	Detail      string `json:"detail"`
}

// IssueState is the live state of one issued code, keyed by code+user.
type IssueState struct {
	Sequence        int64  `json:"sequence"`
	DeviceID        string `json:"device_id"`
	Code            string `json:"code"`
	UserID          string `json:"user_id"`
	IssuedAtRef     int64  `json:"issued_at_ref"`
	WindowMs        int64  `json:"window_ms"`
	ConsumeCount    int    `json:"consume_count"`
	FirstConsumeSeq int64  `json:"first_consume_sequence"`
}

// Key returns the composite key used to correlate issues and consumes.
func IssueKey(code, userID string) string {
	return code + "\x00" + userID
}

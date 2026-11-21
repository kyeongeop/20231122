// Package model defines the normalized Local File Inclusion (LFI) evidence
// record that the review pipeline stores. Both snapshot formats (legacy v1
// flat JSON and current v2 versioned envelope) are decoded into this type.
package model

// ParseStatus classifies how an input object was ingested.
type ParseStatus string

const (
	// StatusOK means the object parsed as a complete evidence record.
	StatusOK ParseStatus = "ok"
	// StatusTruncated means the object was cut off mid-serialization;
	// recovered fields and the raw bytes are retained for review.
	StatusTruncated ParseStatus = "truncated"
	// StatusMalformed means the object could not be interpreted at all.
	StatusMalformed ParseStatus = "malformed"
)

// PermissionDecision is the normalized verdict of the access check that ran
// when the LFI payload was triggered.
type PermissionDecision string

const (
	PermitAll   PermissionDecision = "permit"
	DenyAll     PermissionDecision = "deny"
	PermUnknown PermissionDecision = "unknown"
)

// EvidenceRecord is the single reviewable unit that links the attack input,
// the trigger location, the permission decision and the log evidence.
type EvidenceRecord struct {
	// CorrelationID joins the same incident across the two snapshots.
	CorrelationID string
	// SnapshotVersion is "v1" (legacy) or "v2" (current).
	SnapshotVersion string
	// SourceObject is the object/file name inside the snapshot.
	SourceObject string

	AttackInput string

	TriggerFile   string
	TriggerLine   int
	TriggerSymbol string

	PermissionDecision PermissionDecision
	PermissionRule     string

	LogPath    string
	LogLine    int
	LogSnippet string

	// Status reports whether the object was complete, truncated or malformed.
	Status ParseStatus
	// ParseError holds the recover/parse error text, empty when Status is ok.
	ParseError string

	// Raw is the exact bytes ingested, retained so the truncated prefix can
	// be re-inspected during review.
	Raw []byte
}

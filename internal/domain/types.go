package domain

import "time"

// SchemaVersion is bumped whenever the persisted/exported field layout changes.
const SchemaVersion = 1

// Verdict values produced by the detection engine.
const (
	VerdictConfirmedIDOR  = "CONFIRMED_IDOR"
	VerdictHorizontalIDOR = "HORIZONTAL_IDOR"
	VerdictVerticalIDOR   = "VERTICAL_IDOR"
	VerdictInconclusive   = "INCONCLUSIVE"
	VerdictBenign         = "BENIGN"
)

// Run status values. A run is always persisted before execution so that an
// interrupted process leaves a resumable record behind.
const (
	StatusPending     = "PENDING"
	StatusRunning     = "RUNNING"
	StatusInterrupted = "INTERRUPTED"
	StatusCompleted   = "COMPLETED"
	StatusFailed      = "FAILED"
)

// TenantActor describes the subject of a request: who asks for which tenant.
type TenantActor struct {
	UserID          string `json:"user_id"`
	TenantID        string `json:"tenant_id"`
	Role            string `json:"role"`
	RequestedTenant string `json:"requested_tenant_id"`
	ResourceID      string `json:"resource_id"`
}

// DeviceClock is the clock state of a single device at capture time.
// OffsetNS is device_clock - reference_clock in nanoseconds.
// UncertaintyNS is the residual, unresolvable error after offset correction.
type DeviceClock struct {
	DeviceID      string `json:"device_id"`
	OffsetNS      int64  `json:"offset_ns"`
	UncertaintyNS int64  `json:"uncertainty_ns"`
}

// EvidenceEvent is one captured log/audit record referenced by a sample.
type EvidenceEvent struct {
	Seq        int         `json:"seq"`
	EventID    string      `json:"event_id"`
	DeviceID   string      `json:"device_id"`
	RawTime    time.Time   `json:"raw_time"`
	AdjustedNS int64       `json:"adjusted_ns"`
	Actor      TenantActor `json:"actor"`
	HTTPMethod string      `json:"http_method"`
	Path       string      `json:"path"`
	Decision   string      `json:"decision"`
	Detail     string      `json:"detail"`
}

// MissingFragment documents a time range that cannot be reconstructed because
// the two devices' clocks diverge beyond the calibrated uncertainty.
type MissingFragment struct {
	FragmentID    string `json:"fragment_id"`
	StartNS       int64  `json:"start_ns"`
	EndNS         int64  `json:"end_ns"`
	AnchorEventID string `json:"anchor_event_id"`
	Reason        string `json:"reason"`
}

// Sample is a self-contained, individually re-runnable attack case.
type Sample struct {
	SchemaVersion int             `json:"schema_version"`
	SampleID      string          `json:"sample_id"`
	Title         string          `json:"title"`
	AttackClass   string          `json:"attack_class"`
	Clocks        []DeviceClock   `json:"clocks"`
	Events        []EvidenceEvent `json:"events"`
	Note          string          `json:"note"`
	InputSHA256   string          `json:"input_sha256"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Finding carries the human-reviewable reason for a verdict.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	EventSeq int    `json:"event_seq"`
	EventID  string `json:"event_id"`
	Message  string `json:"message"`
}

// Verdict is the deterministic result of analysing one sample.
type Verdict struct {
	RuleVersion      string            `json:"rule_version"`
	Outcome          string            `json:"outcome"`
	Findings         []Finding         `json:"findings"`
	MissingFragments []MissingFragment `json:"missing_fragments"`
	EvidenceIDs      []string          `json:"evidence_ids"`
}

// Run is one execution attempt of one sample.
type Run struct {
	RunID         string     `json:"run_id"`
	SampleID      string     `json:"sample_id"`
	Attempt       int        `json:"attempt"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	PID           int        `json:"pid"`
	InputSHA256   string     `json:"input_sha256"`
	RuleVersion   string     `json:"rule_version"`
	Outcome       string     `json:"outcome"`
	FindingsJSON  string     `json:"findings_json"`
	FragmentsJSON string     `json:"fragments_json"`
	ErrorText     string     `json:"error_text"`
}

// ExportBundle is the on-disk, independently reviewable export format.
// Field order here is part of the contract and must stay stable.
type ExportBundle struct {
	SchemaVersion    int             `json:"schema_version"`
	BundleID         string          `json:"bundle_id"`
	ToolVersion      string          `json:"tool_version"`
	RuleVersion      string          `json:"rule_version"`
	ExportedAt       time.Time       `json:"exported_at"`
	Sample           Sample          `json:"sample"`
	Run              Run             `json:"run"`
	Verdict          Verdict         `json:"verdict"`
	Evidence         []EvidenceEvent `json:"evidence"`
	ManifestChecksum string          `json:"manifest_checksum"`
}

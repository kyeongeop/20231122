package model

const (
	SchemaVersion = "taintlab/v1"
	ResultSchema  = "taintlab-result/v1"
	ExportSchema  = "taintlab-export/v1"
)

type Scenario struct {
	SchemaVersion string      `json:"schema_version"`
	CaseID        string      `json:"case_id"`
	TraceID       string      `json:"trace_id"`
	Source        Source      `json:"source"`
	Operations    []Operation `json:"operations"`
	Boundary      Boundary    `json:"boundary"`
	Permission    Permission  `json:"permission"`
	Clocks        Clocks      `json:"clocks"`
}

type Source struct {
	Label   string `json:"label"`
	Value   int64  `json:"value"`
	Tainted bool   `json:"tainted"`
}

type Operation struct {
	Seq       int    `json:"seq"`
	Kind      string `json:"kind"`
	Operand   int64  `json:"operand"`
	WidthBits int    `json:"width_bits"`
	Note      string `json:"note,omitempty"`
}

type Boundary struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

type Permission struct {
	Policy        string `json:"policy"`
	RequiredToken int64  `json:"required_token"`
}

type Clocks struct {
	MaxSkewMS int64       `json:"max_skew_ms"`
	DeviceA   DeviceClock `json:"device_a"`
	DeviceB   DeviceClock `json:"device_b"`
}

type DeviceClock struct {
	DeviceID    string `json:"device_id"`
	WallTime    string `json:"wall_time"`
	MonotonicNS int64  `json:"monotonic_ns"`
}

type Result struct {
	SchemaVersion string           `json:"schema_version"`
	CaseID        string           `json:"case_id"`
	TraceID       string           `json:"trace_id"`
	Status        string           `json:"status"`
	Input         InputSummary     `json:"input"`
	Attack        AttackInput      `json:"attack_input"`
	Trigger       Trigger          `json:"trigger"`
	Permission    PermissionResult `json:"permission"`
	Evidence      Evidence         `json:"evidence"`
	Diagnostics   []Diagnostic     `json:"diagnostics"`
}

type InputSummary struct {
	Format           string `json:"format"`
	SizeBytes        int    `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	State            string `json:"state"`
	PreviewHex       string `json:"preview_hex"`
	PreviewTruncated bool   `json:"preview_truncated"`
	RawHex           string `json:"raw_hex"`
	RawComplete      bool   `json:"raw_complete"`
}

type AttackInput struct {
	Source     Source      `json:"source"`
	Operations []Operation `json:"operations"`
	Boundary   Boundary    `json:"boundary"`
	Permission Permission  `json:"permission"`
	Clocks     Clocks      `json:"clocks"`
	TaintPath  []TaintStep `json:"taint_path"`
}

type TaintStep struct {
	Ordinal   int    `json:"ordinal"`
	Seq       int    `json:"seq"`
	Kind      string `json:"kind"`
	Operand   int64  `json:"operand"`
	WidthBits int    `json:"width_bits"`
	Before    int64  `json:"before"`
	After     int64  `json:"after"`
	Tainted   bool   `json:"tainted"`
	Changed   bool   `json:"changed"`
	Wrapped   bool   `json:"wrapped"`
	Location  string `json:"location"`
}

type Trigger struct {
	Detected        bool   `json:"detected"`
	OperationSeq    int    `json:"operation_seq"`
	Location        string `json:"location"`
	Reason          string `json:"reason"`
	Before          int64  `json:"before"`
	After           int64  `json:"after"`
	WidthBits       int    `json:"width_bits"`
	BoundaryCrossed bool   `json:"boundary_crossed"`
	SourceLabel     string `json:"source_label"`
}

type PermissionResult struct {
	Evaluated         bool   `json:"evaluated"`
	Policy            string `json:"policy"`
	RequiredToken     int64  `json:"required_token"`
	CheckValue        int64  `json:"check_value"`
	EffectiveValue    int64  `json:"effective_value"`
	BaselineDecision  string `json:"baseline_decision"`
	EffectiveDecision string `json:"effective_decision"`
	Decision          string `json:"decision"`
	Mismatch          bool   `json:"mismatch"`
	TaintedValue      bool   `json:"tainted_value"`
	TaintedEscalation bool   `json:"tainted_escalation"`
}

type Evidence struct {
	Clock  ClockAnomaly      `json:"clock_anomaly"`
	Events []LogEvent        `json:"events"`
	Key    []EvidencePointer `json:"key_evidence"`
	SHA256 string            `json:"sha256"`
}

type ClockAnomaly struct {
	Detected       bool   `json:"detected"`
	Reason         string `json:"reason"`
	SkewMS         int64  `json:"skew_ms"`
	ThresholdMS    int64  `json:"threshold_ms"`
	WallRegression bool   `json:"wall_regression"`
}

type LogEvent struct {
	Ordinal       int    `json:"ordinal"`
	EventID       string `json:"event_id"`
	DeviceID      string `json:"device_id"`
	Kind          string `json:"kind"`
	CausalOrder   int    `json:"causal_order"`
	WallTime      string `json:"wall_time"`
	MonotonicNS   int64  `json:"monotonic_ns"`
	PayloadSHA256 string `json:"payload_sha256"`
	Detail        string `json:"detail"`
}

type EvidencePointer struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
	Note   string `json:"note"`
}

type Diagnostic struct {
	Ordinal int    `json:"ordinal"`
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

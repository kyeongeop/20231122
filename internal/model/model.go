package model

import "time"

const ReportSchemaVersion = 2

type Recovery struct {
	Key           string            `json:"key"`
	SourceFormat  string            `json:"source_format"`
	RecoveryID    string            `json:"recovery_id"`
	CapturedAt    string            `json:"captured_at"`
	AppVersion    string            `json:"app_version"`
	RNGAlgorithm  string            `json:"rng_algorithm"`
	Seed          string            `json:"seed"`
	RecoveredSeed string            `json:"recovered_seed"`
	StateSHA256   string            `json:"state_sha256"`
	Target        string            `json:"target"`
	Artifact      string            `json:"artifact"`
	Environment   map[string]string `json:"environment"`
	Notes         string            `json:"notes"`
}

type Evidence struct {
	SHA256       string    `json:"sha256"`
	Kind         string    `json:"kind"`
	RelativePath string    `json:"relative_path"`
	Size         int64     `json:"size"`
	MediaType    string    `json:"media_type"`
	CreatedAt    time.Time `json:"created_at"`
}

type TraceStart struct {
	Event          string `json:"event"`
	RestoredSeed   string `json:"restored_seed"`
	InputSeed      string `json:"input_seed"`
	EffectiveSeed  string `json:"effective_seed"`
	Extension      string `json:"extension"`
	KnownExtension bool   `json:"known_extension"`
	Principal      string `json:"principal"`
	Action         string `json:"action"`
}

type TracePermission struct {
	Event     string `json:"event"`
	Extension string `json:"extension"`
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Policy    string `json:"policy"`
	Reason    string `json:"reason"`
}

type TraceTrigger struct {
	Event     string `json:"event"`
	Extension string `json:"extension"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Function  string `json:"function"`
	Kind      string `json:"kind"`
}

type TraceLog struct {
	Event   string `json:"event"`
	Source  string `json:"source"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type Trace struct {
	Starts      []TraceStart
	Permissions []TracePermission
	Triggers    []TraceTrigger
	Logs        []TraceLog
}

type ExtensionRecord struct {
	Name       string           `json:"name"`
	Known      bool             `json:"known"`
	Source     string           `json:"source"`
	Details    map[string]any   `json:"details"`
	Trigger    *TraceTrigger    `json:"trigger,omitempty"`
	Permission *TracePermission `json:"permission,omitempty"`
}

type LogEvidence struct {
	Source         string `json:"source"`
	Sequence       int    `json:"sequence"`
	Level          string `json:"level"`
	Message        string `json:"message"`
	StartOffset    int64  `json:"start_offset"`
	EndOffset      int64  `json:"end_offset"`
	LineSHA256     string `json:"line_sha256"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type Finding struct {
	Code     string         `json:"code"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Details  map[string]any `json:"details"`
}

type ManualCheck struct {
	Code      string `json:"code"`
	Question  string `json:"question"`
	Required  bool   `json:"required"`
	Status    string `json:"status"`
	Owner     string `json:"owner"`
	Notes     string `json:"notes"`
	DecidedAt string `json:"decided_at,omitempty"`
}

type NextAction struct {
	Code   string `json:"code"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

type RunResult struct {
	RunID          int64         `json:"run_id"`
	SessionID      int64         `json:"session_id"`
	Status         string        `json:"status"`
	ExitCode       int           `json:"exit_code"`
	Signal         string        `json:"signal,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
	InputSHA256    string        `json:"input_sha256"`
	InputSize      int64         `json:"input_size"`
	TargetSHA256   string        `json:"target_sha256"`
	EffectiveSeed  string        `json:"effective_seed"`
	FailureCode    string        `json:"failure_code,omitempty"`
	FailureMessage string        `json:"failure_message,omitempty"`
	NextActions    []NextAction  `json:"next_actions"`
	Findings       []Finding     `json:"findings"`
	ManualChecks   []ManualCheck `json:"manual_checks"`
}

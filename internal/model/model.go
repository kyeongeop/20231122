package model

import "time"

type Check struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Source          string     `json:"source"`
	InputName       string     `json:"input_name"`
	RawInput        string     `json:"raw_input"`
	RawSHA256       string     `json:"raw_sha256"`
	CreatedAt       time.Time  `json:"created_at"`
	Status          string     `json:"status"`
	AutoVerdict     string     `json:"auto_verdict"`
	AutoLabel       string     `json:"auto_label"`
	Confidence      float64    `json:"confidence"`
	AutoSummary     string     `json:"auto_summary"`
	AmbiguousRule   string     `json:"ambiguous_rule"`
	AmbiguousNote   string     `json:"ambiguous_note"`
	HumanVerdict    string     `json:"human_verdict"`
	HumanLabel      string     `json:"human_label"`
	HumanReviewer   string     `json:"human_reviewer"`
	HumanNote       string     `json:"human_note"`
	HumanAt         *time.Time `json:"human_at"`
	FuzzerVersion   string     `json:"fuzzer_version"`
	FuzzerExecs     int64      `json:"fuzzer_execs"`
	FuzzerArtifact  string     `json:"fuzzer_artifact"`
	Attempts        []Attempt  `json:"attempts"`
	Evidence        []Evidence `json:"evidence"`
	Audits          []Audit    `json:"audits"`
	Findings        []Finding  `json:"findings"`
	Normalized      string     `json:"normalized"`
	InputSize       int64      `json:"input_size"`
	SelectedAttempt *Attempt   `json:"selected_attempt,omitempty"`
}

type Attempt struct {
	ID            string     `json:"id"`
	CheckID       string     `json:"check_id"`
	Number        int        `json:"number"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at"`
	CancelledBy   string     `json:"cancelled_by"`
	CancelReason  string     `json:"cancel_reason"`
	ErrorCode     string     `json:"error_code"`
	ErrorMessage  string     `json:"error_message"`
	NextActions   []string   `json:"next_actions"`
	EvidenceCount int        `json:"evidence_count"`
	Steps         []Step     `json:"steps"`
}

type Step struct {
	ID            string     `json:"id"`
	AttemptID     string     `json:"attempt_id"`
	Position      int        `json:"position"`
	Phase         string     `json:"phase"`
	Title         string     `json:"title"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at"`
	Summary       string     `json:"summary"`
	InputExcerpt  string     `json:"input_excerpt"`
	OutputExcerpt string     `json:"output_excerpt"`
	Tool          string     `json:"tool"`
	EvidenceIDs   []string   `json:"evidence_ids"`
	Ambiguous     bool       `json:"ambiguous"`
}

type Evidence struct {
	ID        string    `json:"id"`
	CheckID   string    `json:"check_id"`
	AttemptID string    `json:"attempt_id"`
	StepID    string    `json:"step_id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Content   string    `json:"content"`
	Retained  bool      `json:"retained"`
	CreatedAt time.Time `json:"created_at"`
}

type Finding struct {
	ID         string  `json:"id"`
	Rule       string  `json:"rule"`
	Title      string  `json:"title"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Detail     string  `json:"detail"`
	StepID     string  `json:"step_id"`
	EvidenceID string  `json:"evidence_id"`
}

type Audit struct {
	ID        string    `json:"id"`
	CheckID   string    `json:"check_id"`
	AttemptID string    `json:"attempt_id"`
	Event     string    `json:"event"`
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

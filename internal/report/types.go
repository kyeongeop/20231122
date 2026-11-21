package report

type Conclusion struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Statement string `json:"statement"`
	Evidence  string `json:"evidence"`
}

type ManualConfirmation struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	Why      string `json:"why_manual"`
	Evidence string `json:"evidence"`
	Decision string `json:"decision"`
}

type Action struct {
	Condition string `json:"condition"`
	Command   string `json:"command"`
	Purpose   string `json:"purpose"`
}

type StepEvidence struct {
	StepNo            int    `json:"step_no"`
	OpID              string `json:"op_id"`
	Kind              string `json:"kind"`
	Input             string `json:"input"`
	StateBefore       string `json:"state_before"`
	RecordedResult    string `json:"recorded_result"`
	StateAfter        string `json:"state_after"`
	StateBeforeSHA256 string `json:"state_before_sha256"`
	ResultSHA256      string `json:"result_sha256"`
	StateAfterSHA256  string `json:"state_after_sha256"`
	EvidenceSHA256    string `json:"evidence_sha256"`
}

type RunSummary struct {
	RunID            string         `json:"run_id"`
	Scenario         string         `json:"scenario"`
	Role             string         `json:"role"`
	Status           string         `json:"status"`
	StepCount        int            `json:"step_count"`
	InputSHA256      string         `json:"input_sha256"`
	FinalStateSHA256 string         `json:"final_state_sha256"`
	ResolutionSHA256 string         `json:"resolution_sha256"`
	EventSHA256      string         `json:"event_sha256"`
	Steps            []StepEvidence `json:"steps"`
}

type CheckSummary struct {
	RunID    string `json:"run_id"`
	Name     string `json:"name"`
	Scope    string `json:"scope"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
}

type ReplaySummary struct {
	SourceRunID string `json:"source_run_id"`
	ReplayRunID string `json:"replay_run_id"`
	InputMatch  bool   `json:"input_match"`
	StateMatch  bool   `json:"state_match"`
	ResultMatch bool   `json:"result_match"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail"`
}

type FuzzSummary struct {
	Available      bool     `json:"available"`
	Status         string   `json:"status"`
	Executions     int64    `json:"executions"`
	LogPath        string   `json:"log_path"`
	LogSHA256      string   `json:"log_sha256"`
	BinaryPath     string   `json:"binary_path"`
	BinarySHA256   string   `json:"binary_sha256"`
	CorpusFiles    int      `json:"corpus_files"`
	CrashArtifacts []string `json:"crash_artifacts"`
	Detail         string   `json:"detail"`
}

type RuntimeInfo struct {
	GoVersion     string `json:"go_version"`
	SQLiteVersion string `json:"sqlite_version"`
	LibFuzzer     bool   `json:"libfuzzer"`
}

type EvidenceInfo struct {
	DatabasePath       string   `json:"database_path"`
	DatabaseSHA256     string   `json:"database_sha256"`
	Integrity          []string `json:"integrity"`
	ArtifactFiles      []string `json:"artifact_files"`
	EvidenceChainValid bool     `json:"evidence_chain_valid"`
}

type Report struct {
	Schema               string               `json:"schema"`
	GeneratedAtUTC       string               `json:"generated_at_utc"`
	OverallStatus        string               `json:"overall_status"`
	Runtime              RuntimeInfo          `json:"runtime"`
	AutomaticConclusions []Conclusion         `json:"automatic_conclusions"`
	ManualConfirmations  []ManualConfirmation `json:"manual_confirmations"`
	Runs                 []RunSummary         `json:"runs"`
	Checks               []CheckSummary       `json:"checks"`
	Replays              []ReplaySummary      `json:"replays"`
	Fuzz                 FuzzSummary          `json:"libfuzzer"`
	Evidence             EvidenceInfo         `json:"evidence"`
	FailureActions       []Action             `json:"failure_actions"`
}

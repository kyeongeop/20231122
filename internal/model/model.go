package model

import (
	"encoding/json"
	"time"
)

const (
	SchemaVersion = "cacheleak.experiment/v1"
	UnknownExt    = ".q7x"
	UnknownMIME   = "application/octet-stream"
)

type Snapshot struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

type StoredObject struct {
	Key            string    `json:"key"`
	SnapshotID     string    `json:"snapshot_id"`
	Version        string    `json:"version"`
	LogicalPath    string    `json:"logical_path"`
	FileName       string    `json:"file_name"`
	Extension      string    `json:"extension"`
	KnownExtension bool      `json:"known_extension"`
	MIME           string    `json:"mime"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	CapturedAt     time.Time `json:"captured_at"`
	Body           []byte    `json:"-"`
}

type RequestInput struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	SnapshotID string            `json:"snapshot_id"`
	Headers    map[string]string `json:"headers"`
	Submit     int               `json:"submit"`
	RepeatOf   int               `json:"repeat_of,omitempty"`
}

type CacheEntry struct {
	Key        string    `json:"key"`
	SnapshotID string    `json:"snapshot_id"`
	Version    string    `json:"version"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	StoredAt   time.Time `json:"stored_at"`
}

type StepState struct {
	CacheSize       int                   `json:"cache_size"`
	Cache           map[string]CacheEntry `json:"cache"`
	Selected        string                `json:"selected_snapshot"`
	TempRootPresent bool                  `json:"temp_root_present"`
}

type StepResult struct {
	StatusCode       int    `json:"status_code"`
	CacheStatus      string `json:"cache_status"`
	CacheKey         string `json:"cache_key"`
	SelectedSnapshot string `json:"selected_snapshot"`
	ServedSnapshot   string `json:"served_snapshot"`
	ExpectedSHA256   string `json:"expected_sha256"`
	BodySHA256       string `json:"body_sha256"`
	BodySize         int    `json:"body_size"`
	BodyBase64       string `json:"body_base64"`
	MIME             string `json:"mime"`
	Leaked           bool   `json:"leaked"`
	StaleByVersion   bool   `json:"stale_by_version"`
	Error            string `json:"error,omitempty"`
}

type Step struct {
	ID          int64           `json:"id,omitempty"`
	RunID       string          `json:"run_id"`
	ScenarioID  string          `json:"scenario_id"`
	Ordinal     int             `json:"ordinal"`
	ObjectKey   string          `json:"object_key"`
	Phase       string          `json:"phase"`
	Input       RequestInput    `json:"input"`
	StateBefore StepState       `json:"state_before"`
	StateAfter  StepState       `json:"state_after"`
	Result      StepResult      `json:"result"`
	Status      string          `json:"status"`
	ErrorText   string          `json:"error,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  time.Time       `json:"finished_at"`
	EvidenceID  string          `json:"evidence_id,omitempty"`
	Raw         json.RawMessage `json:"-"`
}

type RequestSpec struct {
	ObjectKey  string `json:"object_key"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	SnapshotID string `json:"snapshot_id"`
	Submit     int    `json:"submit"`
	RepeatOf   int    `json:"repeat_of,omitempty"`
	Expect     string `json:"expect"`
}

type ScenarioPlan struct {
	Name       string        `json:"name"`
	Order      string        `json:"order"`
	ResetCache bool          `json:"reset_cache"`
	Requests   []RequestSpec `json:"requests"`
}

type StepSummary struct {
	Ordinal      int    `json:"ordinal"`
	Status       string `json:"status"`
	CacheStatus  string `json:"cache_status"`
	Served       string `json:"served_snapshot"`
	BodySHA256   string `json:"body_sha256"`
	Leaked       bool   `json:"leaked"`
	EvidenceID   string `json:"evidence_id"`
	ErrorMessage string `json:"error,omitempty"`
}

type ScenarioResult struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Order       string        `json:"order"`
	Status      string        `json:"status"`
	StepCount   int           `json:"step_count"`
	ErrorCount  int           `json:"error_count"`
	LeakCount   int           `json:"leak_count"`
	Steps       []StepSummary `json:"steps"`
	TempPath    string        `json:"temp_path"`
	CleanupOK   bool          `json:"cleanup_ok"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  time.Time     `json:"finished_at"`
	ErrorDetail string        `json:"error_detail,omitempty"`
}

type RunSummary struct {
	Schema          string           `json:"schema"`
	ID              string           `json:"id"`
	Status          string           `json:"status"`
	StartedAt       time.Time        `json:"started_at"`
	FinishedAt      time.Time        `json:"finished_at"`
	DBPath          string           `json:"db_path"`
	EvidenceDir     string           `json:"evidence_dir"`
	UnknownExt      string           `json:"unknown_extension"`
	Snapshots       []Snapshot       `json:"snapshots"`
	Objects         []StoredObject   `json:"objects"`
	Scenarios       []ScenarioResult `json:"scenarios"`
	Verifications   []Verification   `json:"verifications"`
	Cleanup         []CleanupRecord  `json:"cleanup"`
	Fuzz            *FuzzResult      `json:"fuzz,omitempty"`
	EvidenceCount   int              `json:"evidence_count"`
	TempPathsLeft   int              `json:"temp_paths_left"`
	KeyEvidencePath string           `json:"key_evidence_path"`
}

type Verification struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Subject    string          `json:"subject"`
	Passed     bool            `json:"passed"`
	Expected   json.RawMessage `json:"expected"`
	Actual     json.RawMessage `json:"actual"`
	EvidenceID string          `json:"evidence_id,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	Detail     string          `json:"detail,omitempty"`
}

type CleanupRecord struct {
	Path          string    `json:"path"`
	ExistedBefore bool      `json:"existed_before"`
	ExistsAfter   bool      `json:"exists_after"`
	Action        string    `json:"action"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	EvidenceID    string    `json:"evidence_id,omitempty"`
}

type FuzzResult struct {
	ID            string    `json:"id"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	Status        string    `json:"status"`
	Command       string    `json:"command"`
	Runs          int       `json:"runs"`
	ExitCode      int       `json:"exit_code"`
	Found         bool      `json:"found"`
	ArtifactPath  string    `json:"artifact_path,omitempty"`
	ArtifactSHA   string    `json:"artifact_sha256,omitempty"`
	LogPath       string    `json:"log_path"`
	LogSHA256     string    `json:"log_sha256"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	SkipReason    string    `json:"skip_reason,omitempty"`
	AssertionText string    `json:"assertion,omitempty"`
}

type Evidence struct {
	ID          string    `json:"id"`
	RunID       string    `json:"run_id"`
	Kind        string    `json:"kind"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	Immutable   bool      `json:"immutable"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

package store

const DefaultSampleID = "C-8842"

type Sample struct {
	ID          string `json:"id"`
	CaseNo      string `json:"case_no"`
	Incident    string `json:"incident"`
	Filename    string `json:"filename"`
	Extension   string `json:"extension"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	Owner       string `json:"owner"`
	ReceivedAt  string `json:"received_at"`
	RecoveredAt string `json:"recovered_at"`
	FrozenAt    string `json:"frozen_at"`
	StoragePath string `json:"storage_path"`
}

type Step struct {
	ID         string `json:"id"`
	SampleID   string `json:"sample_id"`
	Seq        int    `json:"seq"`
	Phase      string `json:"phase"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Command    string `json:"command"`
	Detail     string `json:"detail"`
	Hash       string `json:"hash"`
}

type Evidence struct {
	ID          string `json:"id"`
	SampleID    string `json:"sample_id"`
	StepID      string `json:"step_id"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	MIME        string `json:"mime"`
	SHA256      string `json:"sha256"`
	Size        int    `json:"size"`
	CreatedAt   string `json:"created_at"`
	PreviewHex  string `json:"preview_hex"`
	DownloadURL string `json:"download_url"`
}

type Conclusion struct {
	ID            string   `json:"id"`
	SampleID      string   `json:"sample_id"`
	Origin        string   `json:"origin"`
	Category      string   `json:"category"`
	Title         string   `json:"title"`
	Detail        string   `json:"detail"`
	Status        string   `json:"status"`
	Confidence    float64  `json:"confidence"`
	Severity      string   `json:"severity"`
	RuleID        string   `json:"rule_id"`
	StepID        string   `json:"step_id"`
	EvidenceIDs   []string `json:"evidence_ids"`
	InputRef      string   `json:"input_ref"`
	Boundary      int      `json:"boundary"`
	Undecidable   string   `json:"undecidable_reason"`
	ManualCheckID string   `json:"manual_check_id"`
}

type ManualCheck struct {
	ID           string `json:"id"`
	SampleID     string `json:"sample_id"`
	ConclusionID string `json:"conclusion_id"`
	Question     string `json:"question"`
	Guidance     string `json:"guidance"`
	Status       string `json:"status"`
	Reviewer     string `json:"reviewer"`
	Note         string `json:"note"`
	UpdatedAt    string `json:"updated_at"`
}

type ReplayRun struct {
	ID               string `json:"id"`
	SampleID         string `json:"sample_id"`
	Attempt          int    `json:"attempt"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
	Status           string `json:"status"`
	ExitCode         int    `json:"exit_code"`
	Reproduced       int    `json:"reproduced"`
	Total            int    `json:"total"`
	CrashHash        string `json:"crash_hash"`
	Note             string `json:"note"`
	EvidenceID       string `json:"evidence_id"`
	RecoveredFromJob string `json:"recovered_from_job"`
}

type UnknownExtensionRecord struct {
	ID             string `json:"id"`
	SampleID       string `json:"sample_id"`
	Tag            string `json:"tag"`
	Offset         int    `json:"offset"`
	Length         int    `json:"length"`
	DataOffset     int    `json:"data_offset"`
	Boundary       int    `json:"boundary"`
	RegistryStatus string `json:"registry_status"`
	ParserAction   string `json:"parser_action"`
	RawHex         string `json:"raw_hex"`
	EvidenceID     string `json:"evidence_id"`
}

type Summary struct {
	AutoCount      int    `json:"auto_count"`
	AutoConfirmed  int    `json:"auto_confirmed"`
	AutoUndecided  int    `json:"auto_undecided"`
	ManualCount    int    `json:"manual_count"`
	ManualPending  int    `json:"manual_pending"`
	ManualResolved int    `json:"manual_resolved"`
	EvidenceCount  int    `json:"evidence_count"`
	ReplayCount    int    `json:"replay_count"`
	Status         string `json:"status"`
	StatusLabel    string `json:"status_label"`
}

type Report struct {
	Sample            Sample                   `json:"sample"`
	Steps             []Step                   `json:"steps"`
	Evidence          []Evidence               `json:"evidence"`
	Conclusions       []Conclusion             `json:"conclusions"`
	ManualChecks      []ManualCheck            `json:"manual_checks"`
	Replays           []ReplayRun              `json:"replays"`
	UnknownExtensions []UnknownExtensionRecord `json:"unknown_extensions"`
	Summary           Summary                  `json:"summary"`
	GeneratedAt       string                   `json:"generated_at"`
}

type ExportPackage struct {
	Report   Report             `json:"report"`
	Original string             `json:"original_base64"`
	Evidence []ExportedEvidence `json:"evidence_payloads"`
}

type ExportedEvidence struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	SHA256  string `json:"sha256"`
	Content string `json:"content_base64"`
}

package store

import "mountaudit/internal/audit"

type Run struct {
	ID           string
	CreatedAt    string
	UpdatedAt    string
	SourcePath   string
	SourceName   string
	SourceSize   int64
	SourceSHA256 string
	Original     []byte
	ArtifactPath string
	Format       string
	Status       string
	NextStage    int
	Degraded     bool
	Limits       audit.Limits
	FinalDigest  string
	Error        string
}

type Checkpoint struct {
	RunID        string
	Stage        int
	AnchorNumber int
	Status       string
	StartedAt    string
	FinishedAt   string
	StartOffset  int64
	EndOffset    int64
	AnchorOffset int64
	AnchorLine   int
	SegmentSHA   string
	ResultJSON   string
	ResultSHA    string
	Degraded     bool
}

type RecordRow struct {
	audit.MountRecord
	ObservedAt string
}

type FindingRow struct {
	audit.Finding
	ObservedAt string
}

type Evidence struct {
	Ordinal     int
	Kind        string
	CapturedAt  string
	StartOffset int64
	EndOffset   int64
	SHA256      string
	DetailJSON  string
}

type Comparison struct {
	Ordinal     int
	ComparedAt  string
	Scope       string
	PriorSHA256 string
	CurrentSHA  string
	Equal       bool
	DetailJSON  string
}

type StageCommit struct {
	Checkpoint  Checkpoint
	Records     []RecordRow
	Findings    []FindingRow
	Evidence    []Evidence
	RunStatus   string
	NextStage   int
	Degraded    bool
	FinalDigest string
	UpdatedAt   string
	RunError    string
}

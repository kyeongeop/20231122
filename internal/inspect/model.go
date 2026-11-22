package inspect

import "time"

const (
	VerdictVerified      = "verified"
	VerdictIndeterminate = "indeterminate"
	VerdictError         = "error"
	VerdictPending       = "pending"
)

type Case struct {
	ID         string           `json:"id"`
	Title      string           `json:"title"`
	Target     string           `json:"target"`
	CaseOwner  string           `json:"caseOwner"`
	OpenedAt   string           `json:"openedAt"`
	Objects    []Object         `json:"objects"`
	FuzzRuns   []FuzzRun        `json:"fuzzRuns"`
	Operations []Operation      `json:"operations"`
	Temporary  []TemporaryState `json:"temporary"`
	Stats      Stats            `json:"stats"`
}

type Stats struct {
	Objects       int `json:"objects"`
	Verified      int `json:"verified"`
	Indeterminate int `json:"indeterminate"`
	Errors        int `json:"errors"`
	Evidence      int `json:"evidence"`
	Traced        int `json:"traced"`
}

type Object struct {
	ID            string           `json:"id"`
	Kind          string           `json:"kind"`
	Name          string           `json:"name"`
	Extension     string           `json:"extension"`
	MediaType     string           `json:"mediaType"`
	Version       string           `json:"version"`
	SourceLocator string           `json:"sourceLocator"`
	CapturedAt    string           `json:"capturedAt"`
	SizeBytes     int64            `json:"sizeBytes"`
	SHA256        string           `json:"sha256"`
	Status        string           `json:"status"`
	IsException   bool             `json:"isException"`
	Summary       string           `json:"summary"`
	Snapshots     []Snapshot       `json:"snapshots"`
	Conclusion    *Conclusion      `json:"conclusion,omitempty"`
	Steps         []ProcessingStep `json:"steps"`
	Evidence      []Evidence       `json:"evidence"`
}

type Snapshot struct {
	ID             string `json:"id"`
	ObjectID       string `json:"objectId"`
	Version        string `json:"version"`
	CapturedAt     string `json:"capturedAt"`
	Body           string `json:"body"`
	HeadersJSON    string `json:"headersJson"`
	Signature      string `json:"signature"`
	SignatureAlg   string `json:"signatureAlg"`
	Canonicalizer  string `json:"canonicalizer"`
	VerifierSource string `json:"verifierSource"`
	SourceLine     int    `json:"sourceLine"`
	SourceExcerpt  string `json:"sourceExcerpt"`
}

type Conclusion struct {
	ID           string   `json:"id"`
	Verdict      string   `json:"verdict"`
	Confidence   string   `json:"confidence"`
	Summary      string   `json:"summary"`
	Rationale    string   `json:"rationale"`
	BoundaryNote string   `json:"boundaryNote,omitempty"`
	EvidenceIDs  []string `json:"evidenceIds"`
	CreatedAt    string   `json:"createdAt"`
}

type ProcessingStep struct {
	ID         string `json:"id"`
	ObjectID   string `json:"objectId"`
	Seq        int    `json:"seq"`
	Action     string `json:"action"`
	InputRef   string `json:"inputRef"`
	OutputRef  string `json:"outputRef"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	EvidenceID string `json:"evidenceId"`
}

type Evidence struct {
	ID         string `json:"id"`
	ObjectID   string `json:"objectId"`
	SnapshotID string `json:"snapshotId,omitempty"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Value      string `json:"value"`
	SHA256     string `json:"sha256"`
	ParentID   string `json:"parentId,omitempty"`
	CreatedAt  string `json:"createdAt"`
}

type FuzzRun struct {
	ID             string `json:"id"`
	Target         string `json:"target"`
	Engine         string `json:"engine"`
	CorpusEntries  int    `json:"corpusEntries"`
	Executions     int64  `json:"executions"`
	Crashes        int    `json:"crashes"`
	ArtifactSHA256 string `json:"artifactSha256"`
	ArtifactHex    string `json:"artifactHex"`
	Status         string `json:"status"`
	Note           string `json:"note"`
	CreatedAt      string `json:"createdAt"`
}

type Operation struct {
	ID        string `json:"id"`
	ObjectID  string `json:"objectId"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"createdAt"`
}

type TemporaryState struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Reason    string `json:"reason"`
	Bytes     int64  `json:"bytes"`
	CreatedAt string `json:"createdAt"`
}

type BatchResult struct {
	Processed     int      `json:"processed"`
	Isolated      int      `json:"isolated"`
	Indeterminate int      `json:"indeterminate"`
	Errors        []string `json:"errors,omitempty"`
	Message       string   `json:"message"`
}

type VerificationResult struct {
	Verdict      string
	Confidence   string
	Summary      string
	Rationale    string
	BoundaryNote string
	Steps        []StepResult
	Evidence     []EvidenceDraft
}

type StepResult struct {
	Action    string
	InputRef  string
	OutputRef string
	Status    string
	Detail    string
}

type EvidenceDraft struct {
	Kind     string
	Label    string
	Value    string
	ParentID string
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

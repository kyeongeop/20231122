package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Status string

const (
	StatusPass      Status = "pass"
	StatusWarn      Status = "warn"
	StatusFail      Status = "fail"
	StatusUndecided Status = "undecided"
	StatusTruncated Status = "truncated"
	StatusBlocked   Status = "blocked"
)

type Evidence struct {
	ArtifactID string `json:"artifactId"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Excerpt    string `json:"excerpt"`
	Hash       string `json:"hash"`
	Note       string `json:"note"`
}

type Step struct {
	ID       string    `json:"id"`
	Ordinal  int       `json:"ordinal"`
	Key      string    `json:"key"`
	Label    string    `json:"label"`
	Status   Status    `json:"status"`
	Summary  string    `json:"summary"`
	Detail   string    `json:"detail"`
	Duration int       `json:"durationMs"`
	Evidence *Evidence `json:"evidence,omitempty"`
}

type Artifact struct {
	ID            string `json:"id"`
	AuditID       string `json:"auditId"`
	Label         string `json:"label"`
	Kind          string `json:"kind"`
	MIME          string `json:"mime"`
	Content       string `json:"content"`
	CapturedBytes int    `json:"capturedBytes"`
	ExpectedBytes int    `json:"expectedBytes"`
	SHA256        string `json:"sha256"`
	Immutable     bool   `json:"immutable"`
	Redactions    int    `json:"redactions"`
	Note          string `json:"note"`
}

type Conclusion struct {
	ID       string   `json:"id"`
	Code     string   `json:"code"`
	Status   Status   `json:"status"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	StepID   string   `json:"stepId"`
	Evidence Evidence `json:"evidence"`
}

type Replay struct {
	ID                  string `json:"id"`
	TruncatedAuditID    string `json:"truncatedAuditId"`
	ReplayAuditID       string `json:"replayAuditId"`
	RecoveredArtifactID string `json:"recoveredArtifactId"`
	RecoveredBytes      int    `json:"recoveredBytes"`
	SeamOffset          int    `json:"seamOffset"`
	SeamVerified        bool   `json:"seamVerified"`
	Note                string `json:"note"`
}

type Audit struct {
	ID           string       `json:"id"`
	CaseID       string       `json:"caseId"`
	Label        string       `json:"label"`
	Title        string       `json:"title"`
	Method       string       `json:"method"`
	Target       string       `json:"target"`
	CapturedAt   string       `json:"capturedAt"`
	Source       string       `json:"source"`
	State        string       `json:"state"`
	Verdict      string       `json:"verdict"`
	ReplayOf     string       `json:"replayOf,omitempty"`
	BoundaryNote string       `json:"boundaryNote,omitempty"`
	Steps        []Step       `json:"steps"`
	Artifacts    []Artifact   `json:"artifacts"`
	Conclusions  []Conclusion `json:"conclusions"`
	FirstError   *Step        `json:"firstError,omitempty"`
	Boundary     *Step        `json:"boundary,omitempty"`
	Replay       *Replay      `json:"replay,omitempty"`
	Counts       StatusCounts `json:"counts"`
}

type StatusCounts struct {
	Pass      int `json:"pass"`
	Fail      int `json:"fail"`
	Undecided int `json:"undecided"`
	Blocked   int `json:"blocked"`
	Truncated int `json:"truncated"`
}

type Options struct {
	ExpectedBytes  int
	OriginRedacted bool
	ReplayOf       string
	RecoveredFrom  int
}

type Result struct {
	Steps       []Step
	FirstError  *Step
	Boundary    *Step
	Counts      StatusCounts
	ReplayOK    bool
	ContentHash string
}

func HashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func excerpt(raw []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(raw) {
		end = len(raw)
	}
	if start >= end {
		return ""
	}
	value := strings.TrimSpace(string(raw[start:end]))
	if len(value) > 220 {
		return value[:217] + "..."
	}
	return value
}

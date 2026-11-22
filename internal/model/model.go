package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Format string

const (
	FormatLegacyJSON Format = "legacy-v1"
	FormatLegacySQL  Format = "legacy-sql"
	FormatCurrent    Format = "v2"
)

type Trigger struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Offset int    `json:"offset"`
	Token  string `json:"token"`
}

func (t Trigger) String() string {
	return t.File + ":" + itoa(t.Line) + ":" + itoa(t.Column)
}

type Statement struct {
	Index      int    `json:"index"`
	SQL        string `json:"sql"`
	Target     string `json:"target,omitempty"`
	Source     string `json:"source"`
	BaseLine   int    `json:"base_line"`
	BaseColumn int    `json:"base_column"`
}

type Manifest struct {
	Format        Format      `json:"format"`
	ID            string      `json:"id"`
	Actor         string      `json:"actor"`
	RequestedBy   string      `json:"requested_by,omitempty"`
	ApprovalID    string      `json:"approval_id,omitempty"`
	Statements    []Statement `json:"statements"`
	SourceName    string      `json:"source_name"`
	SourceSHA256  string      `json:"source_sha256"`
	Raw           []byte      `json:"-"`
	Normalized    []byte      `json:"-"`
	ParseWarnings []string    `json:"parse_warnings,omitempty"`
}

type Capability string

const (
	CapRead        Capability = "read"
	CapWrite       Capability = "write"
	CapSchema      Capability = "schema"
	CapDestructive Capability = "destructive"
	CapAttach      Capability = "attach"
	CapAdmin       Capability = "admin"
)

func AllCapabilities() []Capability {
	return []Capability{CapRead, CapWrite, CapSchema, CapDestructive, CapAttach, CapAdmin}
}

type StatementDecision struct {
	Index       int        `json:"index"`
	Keyword     string     `json:"keyword"`
	Capability  Capability `json:"capability"`
	Actor       string     `json:"actor"`
	Granted     []string   `json:"granted"`
	Allowed     bool       `json:"allowed"`
	Reason      string     `json:"reason"`
	Trigger     Trigger    `json:"trigger"`
	Statement   string     `json:"statement"`
	Target      string     `json:"target,omitempty"`
	OperatorOpt string     `json:"operator_option,omitempty"`
}

type PermissionDecision struct {
	Allowed      bool                `json:"allowed"`
	Actor        string              `json:"actor"`
	Format       Format              `json:"format"`
	PolicySHA256 string              `json:"policy_sha256"`
	Statements   []StatementDecision `json:"statements"`
	DenyReason   string              `json:"deny_reason,omitempty"`
	EvaluatedAt  time.Time           `json:"evaluated_at"`
}

type RunStatus string

const (
	StatusRunning   RunStatus = "RUNNING"
	StatusAllowed   RunStatus = "ALLOWED"
	StatusDenied    RunStatus = "DENIED"
	StatusCancelled RunStatus = "CANCELLED"
	StatusFailed    RunStatus = "FAILED"
)

type RunRecord struct {
	RunID         string             `json:"run_id"`
	CreatedAt     time.Time          `json:"created_at"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	Status        RunStatus          `json:"status"`
	Format        Format             `json:"format"`
	ManifestID    string             `json:"manifest_id"`
	Actor         string             `json:"actor"`
	InputPath     string             `json:"input_path"`
	InputSHA256   string             `json:"input_sha256"`
	InputBytes    []byte             `json:"input_bytes,omitempty"`
	Decision      PermissionDecision `json:"decision"`
	Trigger       Trigger            `json:"trigger"`
	Reason        string             `json:"reason"`
	RollbackOK    bool               `json:"rollback_ok"`
	SchemaBefore  string             `json:"schema_before"`
	SchemaAfter   string             `json:"schema_after"`
	LogHeadHash   string             `json:"log_head_hash"`
	EvidenceBytes int64              `json:"evidence_bytes"`
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

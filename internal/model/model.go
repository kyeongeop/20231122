package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	SchemaCase = "serrfix.case/v1"
	SchemaRun  = "serrfix.run/v1"
)

type Params struct {
	MaxOutputBytes   int  `json:"max_output_bytes"`
	MaxSecretBytes   int  `json:"max_secret_bytes"`
	MaxPasses        int  `json:"max_passes"`
	TimeoutMS        int  `json:"timeout_ms"`
	Repetitions      int  `json:"repetitions"`
	UnicodeBoundary  bool `json:"unicode_boundary"`
	AllowInvalidUTF8 bool `json:"allow_invalid_utf8"`
	PreservePrefix   bool `json:"preserve_prefix"`
}

func DefaultParams(label string) Params {
	p := Params{
		MaxOutputBytes:   4096,
		MaxSecretBytes:   8192,
		MaxPasses:        4,
		TimeoutMS:        3000,
		Repetitions:      1,
		UnicodeBoundary:  true,
		AllowInvalidUTF8: true,
		PreservePrefix:   true,
	}
	if containsAny(label, "long", "oversize", "boundary") {
		p.MaxOutputBytes = 16384
		p.MaxSecretBytes = 32768
	}
	if containsAny(label, "unicode") {
		p.UnicodeBoundary = true
	}
	if containsAny(label, "pem", "multiline") {
		p.MaxPasses = 8
	}
	return p
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if len(p) > 0 && bytesContainsFold(s, p) {
			return true
		}
	}
	return false
}

func bytesContainsFold(s, sub string) bool {
	// Labels are ASCII. Keeping this allocation-free is useful during import.
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type SourceRef struct {
	MaterialID string `json:"material_id"`
	Offset     int64  `json:"offset"`
	Length     int64  `json:"length"`
	SHA256     string `json:"sha256"`
}

type Case struct {
	Schema    string    `json:"schema"`
	SampleID  string    `json:"sample_id"`
	Label     string    `json:"label"`
	Origin    string    `json:"origin"`
	Params    Params    `json:"params"`
	Source    SourceRef `json:"source"`
	CreatedAt string    `json:"created_at"`
	Command   string    `json:"rerun_command"`
}

type Sample struct {
	ID         string    `json:"id"`
	Ordinal    int       `json:"ordinal"`
	Label      string    `json:"label"`
	Origin     string    `json:"origin"`
	MaterialID string    `json:"material_id"`
	Offset     int64     `json:"source_offset"`
	Length     int64     `json:"source_length"`
	SHA256     string    `json:"source_sha256"`
	ParamsJSON string    `json:"params_json"`
	CaseJSON   string    `json:"case_json"`
	CreatedAt  time.Time `json:"created_at"`
}

type Span struct {
	Ordinal           int    `json:"ordinal"`
	SourceOffset      int    `json:"source_offset"`
	SourceLength      int    `json:"source_length"`
	Line              int    `json:"line"`
	Column            int    `json:"column"`
	Rule              string `json:"rule"`
	Kind              string `json:"kind"`
	Replacement       string `json:"replacement"`
	ReplacementOffset int    `json:"replacement_offset"`
	OriginalSHA256    string `json:"original_sha256"`
}

type Run struct {
	ID             string    `json:"id"`
	Seq            int64     `json:"seq"`
	SampleID       string    `json:"sample_id"`
	Attempt        int       `json:"attempt"`
	Repetition     int       `json:"repetition"`
	State          string    `json:"state"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	DurationNS     int64     `json:"duration_ns"`
	BeforeLeaks    int       `json:"before_leaks"`
	AfterLeaks     int       `json:"after_leaks"`
	RedactedSHA256 string    `json:"redacted_sha256"`
	EvidencePath   string    `json:"evidence_path"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	Error          string    `json:"error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type RunResult struct {
	Schema          string    `json:"schema"`
	SampleID        string    `json:"sample_id"`
	RunID           string    `json:"run_id"`
	Attempt         int       `json:"attempt"`
	Repetition      int       `json:"repetition"`
	State           string    `json:"state"`
	StartedAt       string    `json:"started_at"`
	FinishedAt      string    `json:"finished_at"`
	DurationNS      int64     `json:"duration_ns"`
	Source          SourceRef `json:"source"`
	Params          Params    `json:"params"`
	BeforeLeaks     int       `json:"before_leaks"`
	AfterLeaks      int       `json:"after_leaks"`
	Spans           []Span    `json:"spans"`
	RedactedSHA256  string    `json:"redacted_sha256"`
	OriginalSHA256  string    `json:"original_sha256"`
	RedactedPreview string    `json:"redacted_preview"`
	EvidenceNote    string    `json:"evidence_note"`
	Error           string    `json:"error,omitempty"`
}

func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func Timestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func ParseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func CanonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

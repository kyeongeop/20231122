package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	SchemaVersion = 1
	CaptureFormat = "proc-self-mountinfo/anchored-v1"
)

type Limits struct {
	MaxInputBytes int64 `json:"max_input_bytes"`
	MaxScanBytes  int64 `json:"max_scan_bytes"`
	MaxRecords    int   `json:"max_records"`
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes: 16 << 20,
		MaxScanBytes:  4 << 20,
		MaxRecords:    4096,
	}
}

func (l Limits) Validate() error {
	if l.MaxInputBytes <= 0 {
		return fmt.Errorf("max input bytes must be positive")
	}
	if l.MaxScanBytes <= 0 {
		return fmt.Errorf("max scan bytes must be positive")
	}
	if l.MaxRecords <= 0 {
		return fmt.Errorf("max records must be positive")
	}
	return nil
}

type Anchor struct {
	Number         int    `json:"number"`
	Label          string `json:"label"`
	Offset         int64  `json:"offset"`
	Line           int    `json:"line"`
	CapturedAt     string `json:"captured_at,omitempty"`
	Explicit       bool   `json:"explicit"`
	DeclaredOffset int64  `json:"declared_offset,omitempty"`
}

func (a Anchor) Stable() StableAnchor {
	return StableAnchor{
		Number:   a.Number,
		Label:    a.Label,
		Offset:   a.Offset,
		Line:     a.Line,
		Explicit: a.Explicit,
	}
}

type StableAnchor struct {
	Number   int    `json:"number"`
	Label    string `json:"label"`
	Offset   int64  `json:"offset"`
	Line     int    `json:"line"`
	Explicit bool   `json:"explicit"`
}

type Permissions struct {
	ReadOnly bool `json:"read_only"`
	NoSUID   bool `json:"no_suid"`
	NoDev    bool `json:"no_dev"`
	NoExec   bool `json:"no_exec"`
}

type MountRecord struct {
	Ordinal      int         `json:"ordinal"`
	Stage        int         `json:"stage"`
	MountID      string      `json:"mount_id"`
	ParentID     string      `json:"parent_id"`
	MajorMinor   string      `json:"major_minor"`
	Root         string      `json:"root"`
	MountPoint   string      `json:"mount_point"`
	MountOptions string      `json:"mount_options"`
	Optional     string      `json:"optional"`
	FSType       string      `json:"fs_type"`
	Source       string      `json:"source"`
	SuperOptions string      `json:"super_options"`
	Permissions  Permissions `json:"permissions"`
	StartOffset  int64       `json:"start_offset"`
	EndOffset    int64       `json:"end_offset"`
	Line         int         `json:"line"`
}

type Finding struct {
	Ordinal     int    `json:"ordinal"`
	Stage       int    `json:"stage"`
	Severity    string `json:"severity"`
	Code        string `json:"code"`
	MountPoint  string `json:"mount_point,omitempty"`
	Source      string `json:"source,omitempty"`
	Detail      string `json:"detail"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	Line        int    `json:"line"`
}

type ParseIssue struct {
	Stage       int    `json:"stage"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	Line        int    `json:"line"`
}

type StageResult struct {
	Schema         string        `json:"schema"`
	Stage          int           `json:"stage"`
	AnchorNumber   int           `json:"anchor_number"`
	AnchorOffset   int64         `json:"anchor_offset"`
	AnchorLine     int           `json:"anchor_line"`
	StartOffset    int64         `json:"start_offset"`
	EndOffset      int64         `json:"end_offset"`
	ScannedBytes   int64         `json:"scanned_bytes"`
	Records        []MountRecord `json:"records"`
	Findings       []Finding     `json:"findings"`
	ParseIssues    []ParseIssue  `json:"parse_issues"`
	Degraded       bool          `json:"degraded"`
	DegradedReason []string      `json:"degraded_reason,omitempty"`
	StopOffset     int64         `json:"stop_offset"`
}

func (s StageResult) Digest() string {
	payload, _ := json.Marshal(s)
	return SHA256Hex(payload)
}

type FinalIdentity struct {
	Schema       string         `json:"schema"`
	SourceSHA256 string         `json:"source_sha256"`
	Anchors      []StableAnchor `json:"anchors"`
	StageDigests []string       `json:"stage_digests"`
}

func FinalDigest(sourceSHA256 string, anchors []Anchor, stageDigests []string) string {
	stableAnchors := make([]StableAnchor, 0, len(anchors))
	for _, anchor := range anchors {
		stableAnchors = append(stableAnchors, anchor.Stable())
	}
	payload, _ := json.Marshal(FinalIdentity{
		Schema:       "mountaudit.final/v1",
		SourceSHA256: sourceSHA256,
		Anchors:      stableAnchors,
		StageDigests: stageDigests,
	})
	return SHA256Hex(payload)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func NowUTC(clock func() time.Time) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock().UTC()
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

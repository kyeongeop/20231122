// Package record defines the audit-log record formats. Two on-disk
// formats coexist and must both be decodable:
//
//	v1 (legacy): pipe-delimited text "v1|<unixts>|<remote>|<xff>|<action>"
//	             an empty XFF field is written as "-"
//	v2 (current): JSON {"v":2,"ts":...,"remote":...,"xff":...,"action":...,
//	             "rule":...,"reason":...}
//
// A record whose bytes are cut short (crash mid-write) must be reported
// as ErrTruncated so the recovery layer can quarantine it as evidence.
package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrTruncated marks a record whose bytes end before the format is complete.
var ErrTruncated = errors.New("record truncated")

const (
	FormatV1 = 1
	FormatV2 = 2
)

// Record is the decoded, format-independent view of one audit entry.
type Record struct {
	Format int    `json:"format"`
	TS     int64  `json:"ts"`
	Remote string `json:"remote"`
	XFF    string `json:"xff"`
	Action string `json:"action"`
	Rule   string `json:"rule,omitempty"`   // v2 only
	Reason string `json:"reason,omitempty"` // v2 only
}

type v2wire struct {
	V      int    `json:"v"`
	TS     int64  `json:"ts"`
	Remote string `json:"remote"`
	XFF    string `json:"xff"`
	Action string `json:"action"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// EncodeV1 renders the legacy pipe-delimited form.
func EncodeV1(r Record) []byte {
	xff := r.XFF
	if xff == "" {
		xff = "-"
	}
	return []byte(fmt.Sprintf("v1|%d|%s|%s|%s", r.TS, r.Remote, xff, r.Action))
}

// EncodeV2 renders the current JSON form.
func EncodeV2(r Record) []byte {
	b, _ := json.Marshal(v2wire{
		V: 2, TS: r.TS, Remote: r.Remote, XFF: r.XFF,
		Action: r.Action, Rule: r.Rule, Reason: r.Reason,
	})
	return b
}

// Detect returns the format number for raw record bytes, or 0 if unknown.
func Detect(raw []byte) int {
	t := bytes.TrimSpace(raw)
	switch {
	case bytes.HasPrefix(t, []byte("v1|")):
		return FormatV1
	case bytes.HasPrefix(t, []byte("{")):
		return FormatV2
	default:
		return 0
	}
}

// Decode parses raw bytes of either format. Truncated input yields
// an error wrapping ErrTruncated.
func Decode(raw []byte) (Record, error) {
	switch Detect(raw) {
	case FormatV1:
		return decodeV1(raw)
	case FormatV2:
		return decodeV2(raw)
	default:
		return Record{}, fmt.Errorf("unknown record format: %w", ErrTruncated)
	}
}

func decodeV1(raw []byte) (Record, error) {
	line := strings.TrimSpace(string(raw))
	parts := strings.Split(line, "|")
	if len(parts) < 5 {
		return Record{}, fmt.Errorf("v1 record has %d of 5 fields: %w", len(parts), ErrTruncated)
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Record{}, fmt.Errorf("v1 bad timestamp: %w", err)
	}
	xff := parts[3]
	if xff == "-" {
		xff = ""
	}
	r := Record{Format: FormatV1, TS: ts, Remote: parts[2], XFF: xff, Action: parts[4]}
	if r.Remote == "" || r.Action == "" {
		return Record{}, fmt.Errorf("v1 empty mandatory field: %w", ErrTruncated)
	}
	return r, nil
}

func decodeV2(raw []byte) (Record, error) {
	t := bytes.TrimSpace(raw)
	var w v2wire
	dec := json.NewDecoder(bytes.NewReader(t))
	if err := dec.Decode(&w); err != nil {
		return Record{}, fmt.Errorf("v2 decode: %v: %w", err, ErrTruncated)
	}
	if w.V != 2 {
		return Record{}, fmt.Errorf("v2 record with version %d", w.V)
	}
	return Record{
		Format: FormatV2, TS: w.TS, Remote: w.Remote, XFF: w.XFF,
		Action: w.Action, Rule: w.Rule, Reason: w.Reason,
	}, nil
}

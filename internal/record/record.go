// Package record normalizes the legacy (v1) and current (v2) snapshot
// record formats into one canonical form and applies the permission
// policy that decides allow/deny for each record.
package record

import (
	"encoding/json"
	"fmt"
)

// Format identifies which snapshot layout a record came from.
type Format int

const (
	FormatUnknown Format = 0
	FormatV1      Format = 1 // legacy: {"id","subject","action","payload"}
	FormatV2      Format = 2 // current: {"version":2,"record_id","principal","op","body"}
)

func (f Format) String() string {
	switch f {
	case FormatV1:
		return "v1"
	case FormatV2:
		return "v2"
	default:
		return "unknown"
	}
}

// Record is the canonical form shared by both snapshot formats.
type Record struct {
	ID      string
	Format  Format
	Subject string // principal requesting the action
	Action  string // requested permission, e.g. "read" / "write"
}

// Decision is the permission verdict for one record.
type Decision string

const (
	Allow           Decision = "allow"
	DenyUnparseable Decision = "deny:unparseable"
	DenyPolicy      Decision = "deny:policy"
)

// allowedActions is the permission allowlist.
var allowedActions = map[string]bool{"read": true, "write": true}

// Judge maps a canonical record to a permission decision.
func Judge(r Record) Decision {
	if !allowedActions[r.Action] {
		return DenyPolicy
	}
	return Allow
}

type v1wire struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Action  string `json:"action"`
}

type v2wire struct {
	Version   int    `json:"version"`
	RecordID  string `json:"record_id"`
	Principal string `json:"principal"`
	Op        string `json:"op"`
}

// Parse detects the snapshot format and normalizes the record. The
// caller must have depth-validated raw already; Parse only handles
// schema-level concerns.
func Parse(raw []byte) (Record, error) {
	var probe struct {
		Version json.Number `json:"version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Record{}, fmt.Errorf("schema decode: %w", err)
	}
	if probe.Version == "2" {
		var w v2wire
		if err := json.Unmarshal(raw, &w); err != nil {
			return Record{}, fmt.Errorf("v2 decode: %w", err)
		}
		if w.RecordID == "" || w.Op == "" {
			return Record{}, fmt.Errorf("v2 record missing record_id/op")
		}
		return Record{ID: w.RecordID, Format: FormatV2, Subject: w.Principal, Action: w.Op}, nil
	}
	var w v1wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Record{}, fmt.Errorf("v1 decode: %w", err)
	}
	if w.ID == "" || w.Action == "" {
		return Record{}, fmt.Errorf("v1 record missing id/action")
	}
	return Record{ID: w.ID, Format: FormatV1, Subject: w.Subject, Action: w.Action}, nil
}

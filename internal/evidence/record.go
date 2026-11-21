package evidence

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/example/jwtconf/internal/ext"
)

// Record correlates one reproduction observation end to end:
// attack input -> trigger location -> permission decision -> log evidence.
//
// FormatV1 is the legacy layout (flat fields, no snapshots).
// FormatV2 adds extension snapshots and structured log references.
// The store and readers accept both formats.
const (
	FormatV1 = 1
	FormatV2 = 2
)

type LogRef struct {
	Seq     int    `json:"seq"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type Record struct {
	Format     int            `json:"format"`
	ID         string         `json:"id"`
	Object     string         `json:"object"`
	AttackHash string         `json:"attack_hash"`
	Trigger    string         `json:"trigger"` // file:line of the permission decision
	Decision   string         `json:"decision"`
	Reason     string         `json:"reason"`
	Logs       []LogRef       `json:"logs"`
	Snaps      []ext.Snapshot `json:"snaps,omitempty"` // v2 only
	CreatedAt  time.Time      `json:"created_at"`
}

// recordV1 is the legacy on-disk shape kept for backward compatibility.
type recordV1 struct {
	ID         string   `json:"id"`
	Object     string   `json:"object"`
	AttackHash string   `json:"attack_hash"`
	Trigger    string   `json:"trigger"`
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason"`
	LogLines   []string `json:"log_lines"`
	CreatedAt  string   `json:"created_at"`
}

// Marshal serializes the record in the requested format.
func Marshal(r Record, format int) ([]byte, error) {
	switch format {
	case FormatV1:
		lines := make([]string, 0, len(r.Logs))
		for _, l := range r.Logs {
			lines = append(lines, fmt.Sprintf("%s %s", l.Level, l.Message))
		}
		return json.Marshal(recordV1{
			ID: r.ID, Object: r.Object, AttackHash: r.AttackHash,
			Trigger: r.Trigger, Decision: r.Decision, Reason: r.Reason,
			LogLines: lines, CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	case FormatV2:
		r.Format = FormatV2
		return json.Marshal(r)
	default:
		return nil, fmt.Errorf("evidence: unknown format %d", format)
	}
}

// Unmarshal accepts both the legacy v1 shape and the current v2 shape.
func Unmarshal(b []byte) (Record, error) {
	var probe struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Record{}, err
	}
	if probe.Format == FormatV2 {
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return Record{}, err
		}
		return r, nil
	}
	var v1 recordV1
	if err := json.Unmarshal(b, &v1); err != nil {
		return Record{}, err
	}
	ts, err := time.Parse(time.RFC3339Nano, v1.CreatedAt)
	if err != nil {
		ts = time.Time{}
	}
	logs := make([]LogRef, 0, len(v1.LogLines))
	for i, l := range v1.LogLines {
		logs = append(logs, LogRef{Seq: i + 1, Level: "legacy", Message: l})
	}
	return Record{
		Format: FormatV1, ID: v1.ID, Object: v1.Object,
		AttackHash: v1.AttackHash, Trigger: v1.Trigger,
		Decision: v1.Decision, Reason: v1.Reason,
		Logs: logs, CreatedAt: ts,
	}, nil
}

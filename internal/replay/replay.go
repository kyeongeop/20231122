// Package replay re-executes recovered audit records through the trust
// boundary and correlates, per record: the attack input, the rule and
// source location that fired, the permission judgment, and the log
// evidence (row id + sha256). It reports the FIRST divergent state
// explicitly instead of collapsing everything into one score.
package replay

import (
	"fmt"

	"trustaudit/internal/record"
	"trustaudit/internal/store"
	"trustaudit/internal/trust"
)

// AttackInput is what the caller actually sent.
type AttackInput struct {
	RemoteAddr string `json:"remote_addr"`
	XFF        string `json:"xff"`
}

// Trigger is where the decision was made.
type Trigger struct {
	Rule     string `json:"rule"`
	Location string `json:"location"`
}

// Judgment is the permission outcome.
type Judgment struct {
	Action   string `json:"action"`
	ClientIP string `json:"client_ip"`
	Reason   string `json:"reason"`
}

// LogEvidence ties a conclusion back to durable storage.
type LogEvidence struct {
	LogID  int64  `json:"log_id"`
	SHA256 string `json:"sha256"`
	Format int    `json:"format"`
}

// Entry is one replayed record with its full correlation.
type Entry struct {
	Evidence       LogEvidence `json:"evidence"`
	Input          AttackInput `json:"attack_input"`
	Trigger        Trigger     `json:"trigger"`
	Judgment       Judgment    `json:"judgment"`
	RecordedAction string      `json:"recorded_action"`
	Match          bool        `json:"match"`
}

// FirstError pinpoints the first state that diverges from expectation.
type FirstError struct {
	LogID      int64  `json:"log_id"`
	Field      string `json:"field"`
	Recorded   string `json:"recorded"`
	Recomputed string `json:"recomputed"`
	Rule       string `json:"rule"`
	Location   string `json:"location"`
	Evidence   string `json:"evidence_sha256"`
	Explain    string `json:"explanation"`
}

// Report is the full replay outcome.
type Report struct {
	FirstError *FirstError `json:"first_error,omitempty"`
	Entries    []Entry     `json:"entries"`
	Total      int         `json:"total"`
	Matched    int         `json:"matched"`
	Mismatched int         `json:"mismatched"`
}

// Replay re-decides every valid record and compares with what was logged.
func Replay(st *store.Store, b *trust.Boundary) (*Report, error) {
	rows, err := st.Entries()
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	for _, row := range rows {
		if row.Status != store.StatusValid {
			continue
		}
		rec, err := record.Decode(row.Raw)
		if err != nil {
			return nil, fmt.Errorf("valid log %d undecodable: %w", row.ID, err)
		}
		d := b.Decide(rec.Remote, rec.XFF)
		e := Entry{
			Evidence: LogEvidence{LogID: row.ID, SHA256: row.SHA256, Format: rec.Format},
			Input:    AttackInput{RemoteAddr: rec.Remote, XFF: rec.XFF},
			Trigger:  Trigger{Rule: d.Rule, Location: d.Location},
			Judgment: Judgment{Action: d.Action, ClientIP: d.ClientIP, Reason: d.Reason},
			RecordedAction: rec.Action,
			Match:          rec.Action == d.Action,
		}
		rep.Total++
		if e.Match {
			rep.Matched++
		} else {
			rep.Mismatched++
			if rep.FirstError == nil {
				rep.FirstError = &FirstError{
					LogID:      row.ID,
					Field:      "action",
					Recorded:   rec.Action,
					Recomputed: d.Action,
					Rule:       d.Rule,
					Location:   d.Location,
					Evidence:   row.SHA256,
					Explain: fmt.Sprintf(
						"log %d recorded %q but replay of remote=%s xff=%q yields %q via %s",
						row.ID, rec.Action, rec.Remote, rec.XFF, d.Action, d.Rule),
				}
			}
		}
		rep.Entries = append(rep.Entries, e)
	}
	return rep, nil
}

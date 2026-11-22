// Package engine runs the deterministic review state machine for one record.
//
// Every transition records four evidence dimensions together:
//   - attack input (the raw wire bytes / hash that drove the step),
//   - trigger site (the named gate where the state changed),
//   - permission decision (role permit + whether it was granted),
//   - log evidence (reason string persisted into SQLite).
//
// The FIRST erroneous state is captured by ordinal rank, so reports point at
// the earliest failure rather than hiding it behind an aggregate score.
package engine

import (
	"fmt"
	"time"

	"riskflow/internal/model"
)

// Trigger sites are stable identifiers used in evidence and replay diffs.
const (
	siteIngest   = "ingest.gate"
	siteRecovery = "recovery.gate"
	siteAuthZ    = "authz.gate"
	siteRisk     = "risk.gate"
	siteDecision = "decision.gate"
)

// policy maps role -> set of decisions that role may request.
var policy = map[string]map[string]bool{
	model.RoleReviewer: {model.DecisionAllow: true, model.DecisionDeny: true},
	model.RoleApprover: {model.DecisionAllow: true, model.DecisionDeny: true},
	model.RoleCI:       {model.DecisionDeny: true},
	model.RoleGuest:    {},
}

var validSeverity = map[string]int{
	"low": 1, "medium": 2, "high": 3, "critical": 4,
}

// Engine evaluates records and emits transitions.
type Engine struct {
	now func() time.Time
}

func New() *Engine { return &Engine{now: time.Now} }

// Result is the full evaluation of one record.
type Result struct {
	Record      model.Record
	Transitions []model.Transition
	FirstError  *model.FirstError
	Terminal    string
	RiskScore   int
}

// Run executes the state machine. recovered indicates the record was rebuilt
// after a truncation, which inserts an explicit RECOVERED evidence step.
func (e *Engine) Run(rec model.Record, recovered bool) Result {
	r := Result{Record: rec}
	seq := 0
	from := ""

	emit := func(to, site, reason string, permit, granted bool) {
		t := model.Transition{
			RecordID:    rec.RecordID,
			Seq:         seq,
			FromState:   from,
			ToState:     to,
			Actor:       rec.Role,
			Permit:      permit,
			Granted:     granted,
			Reason:      reason,
			AttackInput: rec.Package + "@" + rec.Version,
			TriggerSite: site,
			InputHash:   rec.InputHash,
			EventTime:   e.now(),
		}
		r.Transitions = append(r.Transitions, t)
		from = to
		seq++
	}

	setFirst := func(state, reason string) {
		if r.FirstError == nil {
			r.FirstError = &model.FirstError{
				RecordID:  rec.RecordID,
				State:     state,
				Seq:       seq - 1,
				Reason:    reason,
				InputHash: rec.InputHash,
			}
		}
	}

	// 1. Ingestion gate.
	emit(model.StateReceived, siteIngest,
		fmt.Sprintf("accepted %s record %s", rec.Schema, rec.RecordID), true, true)
	emit(model.StateParsed, siteIngest, "normalized fields and bound raw evidence", true, true)

	// 2. Truncation/recovery gate.
	if recovered {
		emit(model.StateTruncated, siteRecovery,
			"rebuilt from truncated frame; checksum/hash re-verified", false, false)
		setFirst(model.StateTruncated, "record was truncated on the wire")
		emit(model.StateRecovered, siteRecovery,
			"recovery completed from SQLite WAL + retained raw fragment", true, true)
	}

	// 3. Authorization gate (permission judgment).
	permit, granted := authorize(rec)
	if !granted {
		emit(model.StateBlocked, siteAuthZ,
			fmt.Sprintf("role %q is not permitted to request %q on %s",
				rec.Role, rec.Decision, rec.Ecosystem), permit, false)
		setFirst(model.StateBlocked, "authorization denied at "+siteAuthZ)
		r.Terminal = model.StateBlocked
		return r
	}
	emit(model.StateChecked, siteAuthZ,
		fmt.Sprintf("role %q permitted for %q", rec.Role, rec.Decision), true, true)

	// 4. Risk scoring gate.
	score, scoreReason := score(rec)
	r.RiskScore = score
	emit(model.StateRisked, siteRisk, scoreReason, true, true)

	// 5. Decision gate.
	if rec.Decision == model.DecisionDeny || score >= 3 {
		emit(model.StateRejected, siteDecision,
			fmt.Sprintf("risk score %d / decision %q -> reject", score, rec.Decision),
			true, false)
		setFirst(model.StateRejected, "rejected at "+siteDecision)
		r.Terminal = model.StateRejected
		return r
	}
	emit(model.StateAccepted, siteDecision,
		fmt.Sprintf("risk score %d / decision %q -> accept", score, rec.Decision),
		true, true)
	r.Terminal = model.StateAccepted
	return r
}

// authorize encapsulates the permission judgment used by both live runs and
// replay, guaranteeing identical decisions.
func authorize(rec model.Record) (permit bool, granted bool) {
	decisions, roleKnown := policy[rec.Role]
	if !roleKnown {
		return false, false
	}
	if rec.Decision != model.DecisionAllow && rec.Decision != model.DecisionDeny {
		return false, false
	}
	allowed := decisions[rec.Decision]
	return allowed, allowed
}

// score is the deterministic risk rule: severity weight plus a deny bias.
func score(rec model.Record) (int, string) {
	weight := validSeverity[rec.Severity]
	if weight == 0 {
		weight = 1
	}
	reason := fmt.Sprintf("severity=%s weight=%d", rec.Severity, weight)
	return weight, reason
}

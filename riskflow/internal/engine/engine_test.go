package engine

import (
	"testing"

	"riskflow/internal/model"
)

func TestAuthorizationGuestBlockedIsFirstError(t *testing.T) {
	rec := model.Record{RecordID: "G1", Package: "p", Version: "1",
		Severity: "low", Decision: model.DecisionAllow, Role: model.RoleGuest,
		InputHash: "h"}
	r := New().Run(rec, false)
	if r.Terminal != model.StateBlocked {
		t.Fatalf("terminal = %s, want BLOCKED", r.Terminal)
	}
	if r.FirstError == nil || r.FirstError.State != model.StateBlocked {
		t.Fatalf("first error = %+v, want BLOCKED", r.FirstError)
	}
	// The block must be the earliest error by rank.
	rank, _ := model.RankOf(model.StateBlocked)
	for _, tr := range r.Transitions {
		if model.IsErrorState(tr.ToState) {
			trRank, _ := model.RankOf(tr.ToState)
			if trRank < rank {
				t.Fatalf("earlier error state %s precedes BLOCKED", tr.ToState)
			}
		}
	}
}

func TestCIBotCannotAllowButCanDeny(t *testing.T) {
	allow := model.Record{RecordID: "C1", Package: "p", Role: model.RoleCI,
		Decision: model.DecisionAllow, InputHash: "h"}
	if r := New().Run(allow, false); r.Terminal != model.StateBlocked {
		t.Fatalf("ci allow terminal = %s, want BLOCKED", r.Terminal)
	}
	deny := model.Record{RecordID: "C2", Package: "p", Role: model.RoleCI,
		Severity: "low", Decision: model.DecisionDeny, InputHash: "h"}
	if r := New().Run(deny, false); r.Terminal != model.StateRejected {
		t.Fatalf("ci deny terminal = %s, want REJECTED", r.Terminal)
	}
}

func TestRecoveryBranchCapturesTruncatedFirst(t *testing.T) {
	rec := model.Record{RecordID: "T1", Package: "p", Version: "1",
		Severity: "low", Decision: model.DecisionAllow, Role: model.RoleApprover,
		InputHash: "h"}
	r := New().Run(rec, true)
	if r.FirstError == nil || r.FirstError.State != model.StateTruncated {
		t.Fatalf("first error = %+v, want TRUNCATED", r.FirstError)
	}
	if r.Terminal != model.StateAccepted {
		t.Fatalf("terminal = %s, want ACCEPTED after recovery", r.Terminal)
	}
}

func TestEvidenceDimensionsBound(t *testing.T) {
	rec := model.Record{RecordID: "E1", Package: "p", Version: "1",
		Severity: "medium", Decision: model.DecisionAllow,
		Role: model.RoleReviewer, InputHash: "hash123"}
	r := New().Run(rec, false)
	for _, tr := range r.Transitions {
		if tr.TriggerSite == "" || tr.AttackInput == "" ||
			tr.InputHash == "" || tr.Reason == "" {
			t.Fatalf("step %d missing evidence: %+v", tr.Seq, tr)
		}
	}
}

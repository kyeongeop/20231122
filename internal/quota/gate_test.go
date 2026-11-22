package quota

import (
	"testing"

	"quotabypass/internal/model"
)

func sampleInput() model.AttackInput {
	return model.AttackInput{
		QuotaCount: 2,
		RejectionResponse: model.RejectionResponse{
			Status: 429, Fragment: "quota_exceeded",
			Body: `{"error":"quota_exceeded"}`,
		},
	}
}

func TestGateQuotaEnforcement(t *testing.T) {
	g := NewGate(2)
	in := sampleInput()
	allow1, status1, _, _ := g.Decide(ModeFixed, in, false)
	allow2, status2, _, _ := g.Decide(ModeFixed, in, false)
	deny, status3, reason, body := g.Decide(ModeFixed, in, false)

	if allow1 != "allow" || allow2 != "allow" || status1 != 200 || status2 != 200 {
		t.Fatalf("expected first two allows, got %s %s", allow1, allow2)
	}
	if deny != "deny" || status3 != 429 || reason != "quota exhausted" ||
		body != in.RejectionResponse.Body {
		t.Fatalf("rejection mismatch: %s %d %s %s", deny, status3, reason, body)
	}
}

func TestGateMissingFragmentModes(t *testing.T) {
	in := sampleInput()

	decision, status, reason, _ := NewGate(2).Decide(ModeVulnerable, in, true)
	if decision != "allow" || status != 200 || reason != "missing rejection fragment: fail-open" {
		t.Fatalf("vulnerable fail-open wrong: %s %d %s", decision, status, reason)
	}

	decision, status, reason, _ = NewGate(2).Decide(ModeFixed, in, true)
	if decision != "deny" || status != 400 || reason != "missing rejection fragment: fail-closed" {
		t.Fatalf("fixed fail-closed wrong: %s %d %s", decision, status, reason)
	}
}

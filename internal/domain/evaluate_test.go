package domain

import "testing"

func defaultFinding() []byte {
	return MustEncodeAttack(Attack{
		ActorRole:     RoleEditor,
		Action:        ActionRead,
		TenantMatch:   true,
		RequestDevice: "device-a",
		SkewAMS:       0,
		SkewBMS:       4500,
	})
}

func TestEvaluateFindsClockSkewPermissionDifference(t *testing.T) {
	evaluation, err := Evaluate(DefaultScenario(), defaultFinding(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if !evaluation.Comparison.PermissionDifference {
		t.Fatalf("expected permission difference: %#v", evaluation.Comparison)
	}
	if evaluation.Evidence.V1.Allow {
		t.Fatalf("v1 should select deleted replica-b")
	}
	if !evaluation.Evidence.V2.Allow {
		t.Fatalf("v2 should select canonical replica-a")
	}
	if evaluation.Evidence.V1.SelectedReplica != "replica-b" {
		t.Fatalf("v1 replica = %s", evaluation.Evidence.V1.SelectedReplica)
	}
	if evaluation.Evidence.V2.SelectedReplica != "replica-a" {
		t.Fatalf("v2 replica = %s", evaluation.Evidence.V2.SelectedReplica)
	}
	if evaluation.FixPlan.RootCause != "duplicate_resolution_clock_skew" {
		t.Fatalf("root cause = %s", evaluation.FixPlan.RootCause)
	}
	if !evaluation.FixPlan.Verified || !evaluation.FixPlan.AfterV1Allow {
		t.Fatalf("canonical resolver fix did not verify: %#v", evaluation.FixPlan)
	}
}

func TestEvaluateAgreesWithoutClockSkew(t *testing.T) {
	input := MustEncodeAttack(Attack{
		ActorRole:     RoleEditor,
		Action:        ActionRead,
		TenantMatch:   true,
		RequestDevice: "device-a",
	})
	evaluation, err := Evaluate(DefaultScenario(), input, "test")
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Comparison.PermissionDifference {
		t.Fatalf("unexpected difference: %#v", evaluation.Comparison)
	}
	if !evaluation.Evidence.V1.Allow || !evaluation.Evidence.V2.Allow {
		t.Fatalf("both versions should allow replica-a: %#v", evaluation.Evidence)
	}
}

func TestCompareFingerprintsHasStableOrder(t *testing.T) {
	left, err := Evaluate(DefaultScenario(), defaultFinding(), "go")
	if err != nil {
		t.Fatal(err)
	}
	right := left
	right.Evidence.V1.Allow = true
	right.Evidence.V2.Allow = false
	right.Evidence.V1.Reason = "changed"
	fields := CompareFingerprints(left.Evidence, right.Evidence)
	want := "v1.allow,v2.allow,v1.reason"
	if got := JoinFields(fields); got != want {
		t.Fatalf("fields = %q, want %q", got, want)
	}
}

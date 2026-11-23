package detect

import (
	"testing"
	"time"

	"idorfix/internal/domain"
)

func sampleWithClocks(uncertainty int64, sameInstant bool) *domain.Sample {
	first := time.Date(2026, 11, 23, 3, 0, 20, 0, time.UTC)
	secondRaw := time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)
	if sameInstant {
		first = time.Date(2026, 11, 23, 3, 0, 10, 0, time.UTC)
		secondRaw = time.Date(2026, 11, 23, 3, 0, 10, 0, time.UTC)
	}
	return &domain.Sample{
		SchemaVersion: domain.SchemaVersion,
		SampleID:      "T-1",
		Clocks: []domain.DeviceClock{
			{DeviceID: "d1", OffsetNS: 10_000_000_000, UncertaintyNS: uncertainty},
			{DeviceID: "d2", OffsetNS: -10_000_000_000, UncertaintyNS: uncertainty},
		},
		Events: []domain.EvidenceEvent{
			{Seq: 1, EventID: "E1", DeviceID: "d1", RawTime: first,
				Actor: domain.TenantActor{UserID: "u1", TenantID: "ta", Role: "member", RequestedTenant: "ta", ResourceID: "r1"}, Decision: "ALLOW", Detail: "u1"},
			{Seq: 2, EventID: "E2", DeviceID: "d2", RawTime: secondRaw,
				Actor: domain.TenantActor{UserID: "u1", TenantID: "ta", Role: "member", RequestedTenant: "tb", ResourceID: "r2"}, Decision: "ALLOW", Detail: "u9"},
		},
	}
}

func TestAnalyseIsDeterministic(t *testing.T) {
	sample := sampleWithClocks(15_000_000_000, true)
	first, err := Analyse(sample)
	if err != nil {
		t.Fatalf("first analyse: %v", err)
	}
	second, err := Analyse(sample)
	if err != nil {
		t.Fatalf("second analyse: %v", err)
	}
	if first.Outcome != second.Outcome {
		t.Fatalf("outcome drift: %s vs %s", first.Outcome, second.Outcome)
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("finding count drift: %d vs %d", len(first.Findings), len(second.Findings))
	}
	if len(first.MissingFragments) != 1 {
		t.Fatalf("expected one missing fragment, got %d", len(first.MissingFragments))
	}
}

func TestGapProducesInconclusiveWhenNoIDOR(t *testing.T) {
	sample := sampleWithClocks(15_000_000_000, true)
	// Remove the cross-tenant request so only the clock gap remains.
	sample.Events[1].Actor.RequestedTenant = "ta"
	sample.Events[1].Detail = "u1"
	verdict, err := Analyse(sample)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if verdict.Outcome != domain.VerdictInconclusive {
		t.Fatalf("expected INCONCLUSIVE, got %s", verdict.Outcome)
	}
}

func TestNoGapWhenClocksArePrecise(t *testing.T) {
	sample := sampleWithClocks(1_000_000, false)
	// Widen the cross-device separation well beyond the 1ms uncertainty so the
	// event ordering is provable and no missing fragment is generated.
	sample.Clocks[0].OffsetNS = 0
	sample.Clocks[1].OffsetNS = 0
	sample.Events[0].RawTime = time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC)
	sample.Events[1].RawTime = time.Date(2026, 11, 23, 3, 0, 30, 0, time.UTC)
	verdict, err := Analyse(sample)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(verdict.MissingFragments) != 0 {
		t.Fatalf("expected no fragments with precise clocks, got %d", len(verdict.MissingFragments))
	}
	if verdict.Outcome != domain.VerdictConfirmedIDOR && verdict.Outcome != domain.VerdictVerticalIDOR {
		t.Fatalf("unexpected outcome %s", verdict.Outcome)
	}
}

func TestUnknownDeviceRejected(t *testing.T) {
	sample := sampleWithClocks(1_000_000, false)
	sample.Events[0].DeviceID = "ghost"
	if _, err := Analyse(sample); err == nil {
		t.Fatal("expected error for unknown device")
	}
}

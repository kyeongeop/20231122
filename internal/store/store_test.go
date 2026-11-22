package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"apiskew.local/apiskew/internal/domain"
)

func TestStorePreservesSampleOrderAndReplayHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apiskew.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	session, err := st.CreateSession(ctx, "sess-test", "test", domain.DefaultScenario())
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "active" || session.Scenario.Object.Key != "invoice:dup-42" {
		t.Fatalf("unexpected session: %#v", session)
	}
	inputs := [][]byte{
		domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 4500}),
		domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleViewer, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 9000}),
		domain.MustEncodeAttack(domain.Attack{ActorRole: domain.RoleOwner, Action: domain.ActionDelete, TenantMatch: true, SkewBMS: 12000}),
	}
	for index, input := range inputs {
		sample, inserted, err := st.InsertSample(ctx, session.ID, "test", input)
		if err != nil {
			t.Fatal(err)
		}
		if !inserted {
			t.Fatalf("sample %d was not inserted", index)
		}
		if sample.Ordinal != index+1 || sample.ID != []string{"s0001", "s0002", "s0003"}[index] {
			t.Fatalf("sample order = %#v", sample)
		}
	}
	duplicate, inserted, err := st.InsertSample(ctx, session.ID, "test", inputs[1])
	if err != nil {
		t.Fatal(err)
	}
	if inserted || duplicate.ID != "s0002" {
		t.Fatalf("duplicate insert = %#v inserted=%t", duplicate, inserted)
	}
	run := Run{
		SessionID:            session.ID,
		SampleID:             "s0002",
		Engine:               "go",
		Status:               "ok",
		V1Allow:              false,
		V2Allow:              true,
		V1Reason:             "selected_replica_deleted",
		V2Reason:             "allow",
		V1Replica:            "replica-b",
		V2Replica:            "replica-a",
		PermissionDifference: true,
		Comparable:           true,
		EvidenceJSON:         `{"sample":"s0002"}`,
		EvidenceSHA256:       domain.SHA256Hex([]byte(`{"sample":"s0002"}`)),
		StartedAt:            "2026-01-01T00:00:00Z",
		CompletedAt:          "2026-01-01T00:00:01Z",
	}
	first, err := st.AddRun(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.AddRun(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if first.Attempt != 1 || second.Attempt != 2 {
		t.Fatalf("attempts = %d,%d", first.Attempt, second.Attempt)
	}
	if err := st.SetSessionStatus(ctx, session.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddEvent(ctx, session.ID, "", "discover_interrupted", map[string]string{"reason": "signal"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	gotSession, err := reopened.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotSession.Status != "paused" || gotSession.Scenario.Object.Replicas[1].Deleted != true {
		t.Fatalf("reloaded session = %#v", gotSession)
	}
	samples, err := reopened.ListSamples(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("samples = %d", len(samples))
	}
	for index, sample := range samples {
		if sample.Ordinal != index+1 || sample.ID != []string{"s0001", "s0002", "s0003"}[index] {
			t.Fatalf("reloaded order = %#v", samples)
		}
	}
	runs, err := reopened.ListRuns(ctx, session.ID, "s0002")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Attempt != 1 || runs[1].Attempt != 2 {
		t.Fatalf("runs = %#v", runs)
	}
	events, err := reopened.ListEvents(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "discover_interrupted" {
		t.Fatalf("events = %#v", events)
	}
	if _, err := reopened.GetSample(ctx, session.ID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing sample error = %v", err)
	}
}

func TestBatchImportContinuesAfterExistingHashes(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "apiskew.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	session, err := st.CreateSession(ctx, "sess-batch", "batch", domain.DefaultScenario())
	if err != nil {
		t.Fatal(err)
	}
	attack := domain.Attack{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 4500}
	inputA := domain.MustEncodeAttack(attack)
	attack.SkewBMS = 9000
	inputB := domain.MustEncodeAttack(attack)
	attack.SkewBMS = 13500
	inputC := domain.MustEncodeAttack(attack)
	items := []ImportItem{
		importItem(t, inputA, attack),
		importItem(t, inputB, attack),
	}
	outcomes, err := st.ImportSamples(ctx, session.ID, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || !outcomes[0].Inserted || outcomes[0].Sample.Ordinal != 1 || outcomes[1].Sample.Ordinal != 2 {
		t.Fatalf("first outcomes = %#v", outcomes)
	}
	items = []ImportItem{
		importItem(t, inputA, attack),
		importItem(t, inputC, attack),
	}
	outcomes, err = st.ImportSamples(ctx, session.ID, items)
	if err != nil {
		t.Fatal(err)
	}
	if outcomes[0].Inserted || outcomes[1].Sample.Ordinal != 3 || !outcomes[1].Inserted {
		t.Fatalf("resume outcomes = %#v", outcomes)
	}
	samples, err := st.ListSamples(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 || samples[2].ID != "s0003" {
		t.Fatalf("samples = %#v", samples)
	}
}

func importItem(t *testing.T, input []byte, attack domain.Attack) ImportItem {
	t.Helper()
	raw := []byte(`{"test":true}`)
	return ImportItem{
		Source: "test",
		Input:  input,
		Attack: attack,
		Run: Run{
			Engine:         "go",
			Status:         "ok",
			V1Allow:        true,
			V2Allow:        true,
			EvidenceJSON:   string(raw),
			EvidenceSHA256: domain.SHA256Hex(raw),
			StartedAt:      "2026-01-01T00:00:00Z",
			CompletedAt:    "2026-01-01T00:00:00Z",
		},
	}
}

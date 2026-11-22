package evidence

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"example.com/migration-review/internal/model"
)

func TestVerifyRunDetectsTamperedLog(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	raw := []byte(`{"id":"tamper","actor":"app_migrator","sql":"DROP TABLE audit_log"}`)
	policySnapshot := []byte(`{"version":1}`)
	trigger := model.Trigger{File: "tamper.json#sql", Line: 1, Column: 1, Token: "DROP"}
	decision := model.PermissionDecision{
		Allowed:      false,
		Actor:        "app_migrator",
		Format:       model.FormatLegacyJSON,
		PolicySHA256: model.SHA256Hex(policySnapshot),
		Statements: []model.StatementDecision{{
			Index: 0, Keyword: "DROP", Capability: model.CapDestructive,
			Actor: "app_migrator", Allowed: false, Trigger: trigger,
		}},
		DenyReason: "denied",
	}
	decisionJSON, _ := json.Marshal(decision)
	record := model.RunRecord{
		RunID:       "tamper-run",
		CreatedAt:   time.Now().UTC(),
		Status:      model.StatusDenied,
		Format:      model.FormatLegacyJSON,
		ManifestID:  "tamper",
		Actor:       "app_migrator",
		InputPath:   "tamper.json",
		InputSHA256: model.SHA256Hex(raw),
		InputBytes:  raw,
		Decision:    decision,
		Trigger:     trigger,
		Reason:      "denied",
	}
	artifacts := []Artifact{
		{Kind: "input", Name: "raw", Content: raw},
		{Kind: "policy", Name: "snapshot.json", Content: policySnapshot},
		{Kind: "permission", Name: "decision.json", Content: decisionJSON},
	}
	if err := store.BeginRun(ctx, record, artifacts...); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Log(ctx, record.RunID, "INFO", "preflight", "start"); err != nil {
		t.Fatal(err)
	}
	last, err := store.Log(ctx, record.RunID, "DENY", "permission_decision", "denied")
	if err != nil {
		t.Fatal(err)
	}
	record.LogHeadHash = last.Hash
	now := time.Now().UTC()
	record.CompletedAt = &now
	if err := store.CompleteRun(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyRun(ctx, record.RunID); err != nil {
		t.Fatalf("initial verification failed: %v", err)
	}
	if _, err := store.db.ExecContext(ctx,
		"UPDATE logs SET detail = 'tampered' WHERE run_id = ? AND event = 'permission_decision'",
		record.RunID); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyRun(ctx, record.RunID); err == nil {
		t.Fatal("tampered log passed verification")
	}
}

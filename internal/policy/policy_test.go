package policy_test

import (
	"os"
	"strings"
	"testing"

	"example.com/migration-review/internal/manifest"
	"example.com/migration-review/internal/model"
	"example.com/migration-review/internal/policy"
)

func TestMigrationActorCannotDropAuditTable(t *testing.T) {
	engine := loadEngine(t)
	m := loadManifest(t)
	decision := engine.Authorize(m, policy.Options{})
	if decision.Allowed {
		t.Fatal("destructive attack was allowed")
	}
	if len(decision.Statements) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decision.Statements))
	}
	if !decision.Statements[0].Allowed || decision.Statements[0].Capability != model.CapSchema {
		t.Fatalf("first statement should be allowed schema change: %#v", decision.Statements[0])
	}
	attack := decision.Statements[1]
	if attack.Allowed || attack.Capability != model.CapDestructive || attack.Keyword != "DROP" {
		t.Fatalf("destructive statement not denied correctly: %#v", attack)
	}
	if attack.Trigger.File != "legacy-drop-audit.json#sql" || attack.Trigger.Line != 3 || attack.Trigger.Column != 1 {
		t.Fatalf("wrong trigger: %#v", attack.Trigger)
	}
	if !strings.Contains(decision.DenyReason, attack.Trigger.String()) {
		t.Fatalf("deny reason lacks trigger mapping: %s", decision.DenyReason)
	}
}

func TestCommentAndStringDoNotBypassPolicy(t *testing.T) {
	cases := []struct {
		sql  string
		cap  model.Capability
		word string
	}{
		{"-- DROP TABLE audit_log\nSELECT 1", model.CapRead, "SELECT"},
		{"SELECT 'DROP TABLE audit_log'", model.CapRead, "SELECT"},
		{"/* harmless */ WITH x AS (SELECT 1) DELETE FROM accounts", model.CapWrite, "DELETE"},
		{"PRAGMA writable_schema = ON", model.CapAdmin, "PRAGMA"},
		{"ATTACH DATABASE '/tmp/x.db' AS x", model.CapAttach, "ATTACH"},
	}
	for _, tc := range cases {
		engine, err := policy.Load([]byte(`{"version":1,"actors":{"admin":{"capabilities":["read","write","schema","destructive","attach","admin"]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		m, err := manifest.Parse([]byte(tc.sql), "case.sql")
		if err != nil {
			t.Fatal(err)
		}
		d := engine.Authorize(m, policy.Options{AllowDestructive: true, AllowAttach: true, AllowAdmin: true, ApprovalID: "ok"})
		if len(d.Statements) != 1 || d.Statements[0].Capability != tc.cap || d.Statements[0].Keyword != tc.word {
			t.Fatalf("%q: got %#v", tc.sql, d.Statements)
		}
	}
}

func TestDangerousCapabilitiesNeedOperatorGate(t *testing.T) {
	engine, err := policy.Load([]byte(`{"version":1,"actors":{"admin":{"capabilities":["read","write","schema","destructive","attach","admin"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse([]byte(`{"id":"drop","actor":"admin","sql":"DROP TABLE audit_log"}`), "drop.json")
	if err != nil {
		t.Fatal(err)
	}
	noFlag := engine.Authorize(m, policy.Options{ApprovalID: "CHG-1"})
	if noFlag.Allowed || !strings.Contains(noFlag.DenyReason, "--allow-destructive") {
		t.Fatalf("missing operator flag was allowed: %#v", noFlag)
	}
	noApproval := engine.Authorize(m, policy.Options{AllowDestructive: true})
	if noApproval.Allowed || !strings.Contains(noApproval.DenyReason, "--approval-id") {
		t.Fatalf("missing approval id was allowed: %#v", noApproval)
	}
	allowed := engine.Authorize(m, policy.Options{AllowDestructive: true, ApprovalID: "CHG-1"})
	if !allowed.Allowed {
		t.Fatalf("fully gated destructive action denied: %s", allowed.DenyReason)
	}
}

func loadEngine(t *testing.T) *policy.Engine {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func loadManifest(t *testing.T) *model.Manifest {
	t.Helper()
	data, err := os.ReadFile("../../testdata/attack/legacy-drop-audit.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(data, "legacy-drop-audit.json")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

package fuzz_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"example.com/migration-review/internal/fuzzcheck"
	"example.com/migration-review/internal/policy"
)

func FuzzReview(f *testing.F) {
	seeds, err := filepath.Glob("corpus/*")
	if err != nil {
		f.Fatal(err)
	}
	for _, path := range seeds {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"format_version":2,"migration":{"id":"empty","actor":"app_migrator","statements":[]}}`))
	f.Add([]byte(`{"id":"legacy","actor":"app_migrator","sql":"/*x*/ ALTER TABLE t ADD COLUMN c TEXT; DROP TABLE audit_log;"}`))

	engine := loadPolicy(f)
	permissive, err := policy.Load([]byte(`{"version":1,"actors":{"admin":{"capabilities":["read","write","schema","destructive","attach","admin"]}}}`))
	if err != nil {
		f.Fatal(err)
	}
	allowAll := policy.Options{AllowDestructive: true, AllowAttach: true, AllowAdmin: true, ApprovalID: "fuzz"}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, decision, err := fuzzcheck.Evaluate(data, engine)
		if err != nil {
			return
		}
		if len(m.Normalized) == 0 {
			t.Fatal("parsed manifest has no normalized evidence")
		}
		var normalized map[string]any
		if err := json.Unmarshal(m.Normalized, &normalized); err != nil {
			t.Fatalf("normalized evidence is not JSON: %v", err)
		}
		if len(decision.Statements) != len(m.Statements) {
			t.Fatalf("decision count %d != statement count %d", len(decision.Statements), len(m.Statements))
		}
		for _, statement := range decision.Statements {
			if statement.Trigger.File == "" || statement.Trigger.Line < 1 {
				t.Fatalf("missing trigger location: %#v", statement.Trigger)
			}
		}
		if decision.Allowed {
			for _, statement := range decision.Statements {
				if !statement.Allowed {
					t.Fatalf("global allow with denied statement: %#v", statement)
				}
			}
		}
		alternate := permissive.Authorize(m, allowAll)
		if len(alternate.Statements) != len(m.Statements) {
			t.Fatalf("alternate policy statement mismatch")
		}
	})
}

func loadPolicy(t testing.TB) *policy.Engine {
	t.Helper()
	data, err := os.ReadFile("../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

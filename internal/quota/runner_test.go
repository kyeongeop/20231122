package quota

import "testing"

func expectedSummary() map[string]struct {
	allowed, denied int
	bypass          bool
	decision        string
	authorized      bool
} {
	return map[string]struct {
		allowed, denied int
		bypass          bool
		decision        string
		authorized      bool
	}{
		"baseline-complete":        {4, 20, false, "allow", true},
		"attack-missing-fragment":  {24, 0, true, "allow", false},
		"control-missing-fragment": {0, 24, false, "deny", true},
		"capacity-pressure":        {3, 61, false, "allow", true},
		"empty-input":              {0, 0, false, "deny", false},
		"oversized-input":          {0, 0, false, "deny", false},
	}
}

func TestRunnerSummariesMatchReference(t *testing.T) {
	want := expectedSummary()
	for i, sc := range DefaultScenarios() {
		rec := NewRunner(sc.Mode).Run(sc.Name, i, sc.Raw)
		w := want[sc.Name]
		if rec.Summary.Allowed != w.allowed || rec.Summary.Denied != w.denied ||
			rec.Summary.BypassDetected != w.bypass {
			t.Fatalf("%s summary = %+v, want allowed=%d denied=%d bypass=%v",
				sc.Name, rec.Summary, w.allowed, w.denied, w.bypass)
		}
		if rec.Permission.Decision != w.decision ||
			rec.Permission.Authorized != w.authorized {
			t.Fatalf("%s permission = %+v", sc.Name, rec.Permission)
		}
		if len(rec.Attempts) != rec.AttackInput.ConcurrentRequests {
			t.Fatalf("%s attempts=%d requests=%d", sc.Name,
				len(rec.Attempts), rec.AttackInput.ConcurrentRequests)
		}
	}
}

func TestAttackEvidenceChain(t *testing.T) {
	specs := DefaultScenarios()
	attack := specs[1]
	rec := NewRunner(attack.Mode).Run(attack.Name, 1, attack.Raw)

	if !rec.Summary.BypassDetected {
		t.Fatal("attack must be flagged as bypass")
	}
	if rec.Permission.Trigger.File != GateFile || rec.Permission.Trigger.Line != GateLine {
		t.Fatalf("permission trigger drift: %+v", rec.Permission.Trigger)
	}
	foundMissing, foundBypass := false, false
	for _, l := range rec.Logs {
		if l.Event == "missing_fragments" && l.Message == "fields=[rejection_response.fragment]" {
			foundMissing = true
		}
		if l.Event == "quota_bypass_detected" {
			foundBypass = true
		}
	}
	if !foundMissing || !foundBypass {
		t.Fatalf("evidence chain incomplete: missing=%v bypass=%v logs=%d",
			foundMissing, foundBypass, len(rec.Logs))
	}
	// 每个 attempt 的触发器都指向同一权限判断点。
	for _, a := range rec.Attempts {
		if a.Trigger.Function != GateFunction || a.HTTPStatus != 200 {
			t.Fatalf("attempt evidence drift: %+v", a)
		}
	}
}

func TestDeterministicReplay(t *testing.T) {
	specs := DefaultScenarios()
	first := NewRunner(ModeVulnerable).Run(specs[1].Name, 1, specs[1].Raw)
	second := NewRunner(ModeVulnerable).Run(specs[1].Name, 1, specs[1].Raw)
	if first.RecordSHA256 != second.RecordSHA256 {
		t.Fatalf("non-deterministic record hash: %s vs %s",
			first.RecordSHA256, second.RecordSHA256)
	}
	if first.RunID != second.RunID {
		t.Fatalf("run id drift: %s vs %s", first.RunID, second.RunID)
	}
}

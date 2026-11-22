package quota

import (
	"sort"
	"testing"
)

func TestLogEventSequences(t *testing.T) {
	wantEvents := map[string][]string{
		"baseline-complete":        append([]string{"input_evidence"}, repeat("attempt_decision", 24)...),
		"attack-missing-fragment":  {"input_evidence", "missing_fragments"},
		"control-missing-fragment": {"input_evidence", "missing_fragments"},
		"capacity-pressure":        append([]string{"input_evidence"}, repeat("attempt_decision", 64)...),
		"empty-input":              {"input_evidence", "quota_enforced"},
		"oversized-input":          {"input_evidence", "quota_enforced"},
	}
	for i, sc := range DefaultScenarios() {
		rec := NewRunner(sc.Mode).Run(sc.Name, i, sc.Raw)
		got := make([]string, 0, len(rec.Logs))
		for _, l := range rec.Logs {
			got = append(got, l.Event)
		}
		sort.Strings(got)
		want := append([]string(nil), wantEvents[sc.Name]...)
		if sc.Name == "attack-missing-fragment" || sc.Name == "control-missing-fragment" {
			want = append(want, repeat("attempt_decision", 24)...)
			want = append(want, terminalEvent(rec.Summary.BypassDetected))
		} else if sc.Name == "baseline-complete" || sc.Name == "capacity-pressure" {
			want = append(want, "quota_enforced")
		}
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("%s: %d events != %d", sc.Name, len(got), len(want))
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("%s event mismatch at %d: %s != %s",
					sc.Name, j, got[j], want[j])
			}
		}
	}
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func terminalEvent(bypass bool) string {
	if bypass {
		return "quota_bypass_detected"
	}
	return "quota_enforced"
}

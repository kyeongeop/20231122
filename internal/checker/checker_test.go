package checker

import "testing"

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    Verdict
	}{
		{"bypass", "policy.auth_required: true\nrequest.credential: none\nresponse.status: 101", VerdictBypassDetected},
		{"rejected", "policy.auth_required: true\nrequest.credential: none\nresponse.status: 401", VerdictNoBypass},
		{"auth-ok", "policy.auth_required: true\nrequest.credential: bearer xyz\nresponse.status: 101", VerdictNoBypass},
		{"dropped", "policy.auth_required: true\nrequest.credential: none\nresponse.connection: reset", VerdictUndetermined},
		{"truncated", "response.status: 101\ncapture.truncated: true", VerdictUndetermined},
		{"unknown-policy", "request.credential: none\nresponse.status: 101", VerdictUndetermined},
		{"odd-status", "policy.auth_required: true\nrequest.credential: none\nresponse.status: 302", VerdictUndetermined},
		{"garbage", "\x00\xff not a scenario", VerdictUndetermined},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Evaluate(Input{Label: tc.name, Content: tc.content})
			if res.Verdict != tc.want {
				t.Fatalf("verdict=%s want %s", res.Verdict, tc.want)
			}
			if len(res.Steps) < 3 {
				t.Fatalf("expected lineage steps, got %d", len(res.Steps))
			}
			if res.Verdict == VerdictUndetermined && len(res.Evidence) == 0 && tc.name != "garbage" {
				t.Fatalf("undetermined verdict should retain evidence")
			}
		})
	}
}

func TestDigestStable(t *testing.T) {
	in := Input{Content: "response.status: 101"}
	if in.Digest() != in.Digest() || len(in.Digest()) != 64 {
		t.Fatal("digest must be a stable sha256 hex string")
	}
}

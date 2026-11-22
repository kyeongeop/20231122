package audit

import (
	"strings"
	"testing"
)

func fixtureByID(t *testing.T, id string) Audit {
	t.Helper()
	for _, item := range SeedAudits() {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("fixture %s not found", id)
	return Audit{}
}

func step(t *testing.T, item Audit, key string) Step {
	t.Helper()
	for _, candidate := range item.Steps {
		if candidate.Key == key {
			return candidate
		}
	}
	t.Fatalf("step %s not found", key)
	return Step{}
}

func TestTruncatedCaptureStopsAtFirstError(t *testing.T) {
	item := fixtureByID(t, TruncatedAuditID)
	if item.FirstError == nil || item.FirstError.Key != "capture.complete" {
		t.Fatalf("first error = %#v, want capture.complete", item.FirstError)
	}
	if item.FirstError.Status != StatusTruncated {
		t.Fatalf("first error status = %s, want truncated", item.FirstError.Status)
	}
	if item.Counts.Truncated != 1 || item.Counts.Blocked != 5 {
		t.Fatalf("counts = %#v, want 1 truncated and 5 blocked", item.Counts)
	}
	if item.Counts.Pass != 0 || item.Counts.Fail != 0 {
		t.Fatalf("truncated capture must not contain pass/fail, got %#v", item.Counts)
	}
	for _, key := range []string{"frame.parse", "headers.parse", "policy.origin", "policy.credentials", "policy.vary"} {
		if got := step(t, item, key).Status; got != StatusBlocked {
			t.Errorf("%s status = %s, want blocked", key, got)
		}
	}
}

func TestReplayPreservesUndecidedBoundaryAndFirstError(t *testing.T) {
	item := fixtureByID(t, ReplayAuditID)
	if item.FirstError == nil {
		t.Fatal("replay has no first error")
	}
	if item.FirstError.Key != "policy.vary" || item.FirstError.Ordinal != 6 {
		t.Fatalf("first error = %s/%d, want policy.vary/6", item.FirstError.Key, item.FirstError.Ordinal)
	}
	if item.Boundary == nil || item.Boundary.Key != "policy.origin" || item.Boundary.Status != StatusUndecided {
		t.Fatalf("boundary = %#v, want undecided policy.origin", item.Boundary)
	}
	if !strings.Contains(item.Boundary.Evidence.Excerpt, "REDACTED:origin") {
		t.Fatalf("boundary evidence lost redaction marker: %q", item.Boundary.Evidence.Excerpt)
	}
	if item.Counts.Pass != 5 || item.Counts.Fail != 1 || item.Counts.Undecided != 1 {
		t.Fatalf("counts = %#v, want 5 pass / 1 fail / 1 undecided", item.Counts)
	}
	if item.Replay == nil || !item.Replay.SeamVerified {
		t.Fatalf("replay seam not verified: %#v", item.Replay)
	}
}

func TestRecoveredChunkReconstructsFullCapture(t *testing.T) {
	truncated := fixtureByID(t, TruncatedAuditID)
	replay := fixtureByID(t, ReplayAuditID)
	if len(truncated.Artifacts) != 1 || len(replay.Artifacts) != 2 {
		t.Fatalf("unexpected fixture artifacts: trunc=%d replay=%d", len(truncated.Artifacts), len(replay.Artifacts))
	}
	prefix := truncated.Artifacts[0].Content
	full := replay.Artifacts[0].Content
	chunk := replay.Artifacts[1].Content
	if !strings.HasPrefix(full, prefix) {
		t.Fatal("replay no longer preserves the truncated prefix byte-for-byte")
	}
	if prefix+chunk != full {
		t.Fatal("recovered chunk does not append to the preserved prefix")
	}
	if replay.Replay.SeamOffset != len(prefix) || replay.Replay.RecoveredBytes != len(chunk) {
		t.Fatalf("seam metadata mismatch: %#v", replay.Replay)
	}
	if replay.Artifacts[0].SHA256 != HashBytes([]byte(full)) {
		t.Fatal("replay artifact hash does not bind the original bytes")
	}
}

func TestEveryConclusionResolvesToStepAndEvidence(t *testing.T) {
	for _, item := range SeedAudits() {
		artifacts := map[string]Artifact{}
		for _, artifact := range item.Artifacts {
			artifacts[artifact.ID] = artifact
		}
		steps := map[string]Step{}
		for _, candidate := range item.Steps {
			steps[candidate.ID] = candidate
			if candidate.Evidence == nil {
				continue
			}
			artifact, ok := artifacts[candidate.Evidence.ArtifactID]
			if !ok {
				t.Errorf("%s step %s points to unknown artifact %q", item.ID, candidate.Key, candidate.Evidence.ArtifactID)
				continue
			}
			if candidate.Evidence.End > len(artifact.Content) || candidate.Evidence.Start < 0 || candidate.Evidence.End < candidate.Evidence.Start {
				t.Errorf("%s step %s evidence range %d..%d outside %d bytes",
					item.ID, candidate.Key, candidate.Evidence.Start, candidate.Evidence.End, len(artifact.Content))
			}
		}
		for _, conclusion := range item.Conclusions {
			if _, ok := steps[conclusion.StepID]; !ok {
				t.Errorf("%s conclusion %s points to unknown step %q", item.ID, conclusion.Code, conclusion.StepID)
			}
			if conclusion.Evidence.ArtifactID == "" {
				t.Errorf("%s conclusion %s has no evidence artifact", item.ID, conclusion.Code)
				continue
			}
			artifact, ok := artifacts[conclusion.Evidence.ArtifactID]
			if !ok {
				t.Errorf("%s conclusion %s points to unknown artifact", item.ID, conclusion.Code)
				continue
			}
			if conclusion.Evidence.End > len(artifact.Content) {
				t.Errorf("%s conclusion %s evidence escapes artifact", item.ID, conclusion.Code)
			}
		}
	}
}

func TestOpaqueOriginIsExplicitlyUndecided(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\nHost: api.example.com\nOrigin: null\n\n" +
		"HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true\nVary: Origin\n\n")
	result := Analyze(raw, Options{ExpectedBytes: len(raw)})
	if result.Boundary == nil || result.Boundary.Key != "policy.origin" {
		t.Fatalf("boundary = %#v, want policy.origin", result.Boundary)
	}
	if result.Boundary.Status != StatusUndecided || !strings.Contains(result.Boundary.Detail, "opaque origin") {
		t.Fatalf("opaque origin not preserved as undecided: %#v", result.Boundary)
	}
}

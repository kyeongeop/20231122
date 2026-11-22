package replay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seedreview/internal/evidence"
	"seedreview/internal/manifest"
	"seedreview/internal/model"
	"seedreview/internal/report"
	"seedreview/internal/store"
)

const successTrace = `{"event":"start","restored_seed":"0","input_seed":"0","effective_seed":"0","extension":"hook.v2","known_extension":false,"principal":"guest","action":"execute"}
{"event":"permission","extension":"hook.v2","principal":"guest","action":"execute","expected":"deny","actual":"deny","policy":"unknown-extension-deny","reason":"unknown extension is denied by default"}
{"event":"trigger","extension":"hook.v2","file":"fuzz/seed_target.c","line":191,"function":"evaluate_permission","kind":"permission_gate"}
{"event":"log","source":"seed_target","level":"warn","message":"unknown_extension_denied"}
`

func TestReplayMapsUnknownExtensionToEvidence(t *testing.T) {
	parsed, database, evidenceStore := testHarness(t, successTargetScript())
	engine := New(Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		Timeout: 5 * time.Second,
	})
	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != "ok" || result.SessionID == 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	view, err := database.GetRun(context.Background(), result.RunID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if view.AutoConclusion != "unknown_extension_denied" {
		t.Fatalf("AutoConclusion = %q", view.AutoConclusion)
	}
	if len(view.Extensions) != 1 || view.Extensions[0].Name != "hook.v2" {
		t.Fatalf("extensions = %#v", view.Extensions)
	}
	if view.Extensions[0].Trigger == nil || view.Extensions[0].Trigger.Line != 191 {
		t.Fatalf("trigger = %#v", view.Extensions[0].Trigger)
	}
	if view.Extensions[0].Permission == nil || view.Extensions[0].Permission.Actual != "deny" {
		t.Fatalf("permission = %#v", view.Extensions[0].Permission)
	}
	if len(view.Logs) != 2 {
		t.Fatalf("logs = %#v", view.Logs)
	}
	if len(view.Evidence) != 6 {
		t.Fatalf("evidence count = %d", len(view.Evidence))
	}
	if !hasFinding(view.Findings, "ZERO_SEED_AFTER_RECOVERY") {
		t.Fatalf("findings = %#v", view.Findings)
	}
}

func TestReplayFailureIsPreservedWithNextActions(t *testing.T) {
	parsed, database, evidenceStore := testHarness(t, successTargetScript())
	parsed.Recovery.Target = filepath.Join(t.TempDir(), "missing-target")
	engine := New(Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		Timeout: 5 * time.Second,
	})
	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != "failed" || result.FailureCode != "target_missing" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !hasAction(result.NextActions, "BUILD_TARGET") {
		t.Fatalf("next actions = %#v", result.NextActions)
	}
	built, err := report.Build(context.Background(), database, evidenceStore, result.RunID)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.Automatic.Failure.Code != "target_missing" {
		t.Fatalf("failure = %#v", built.Automatic.Failure)
	}
	markdown := report.Markdown(built)
	if !strings.Contains(markdown, "## 自动结论") ||
		!strings.Contains(markdown, "## 人工确认") ||
		!strings.Contains(markdown, "BUILD_TARGET") {
		t.Fatalf("markdown sections missing:\n%s", markdown)
	}
}

func TestRunKeepsActualArtifactPathWhenManifestIsReused(t *testing.T) {
	parsed, database, evidenceStore := testHarness(t, successTargetScript())
	firstArtifact := parsed.Recovery.Artifact
	secondArtifact := filepath.Join(filepath.Dir(firstArtifact), "second-artifact.bin")
	if err := os.WriteFile(secondArtifact, []byte("SEEDAUDIT1\next=hook.v2\nseed=0\nprobe=2\n"), 0o644); err != nil {
		t.Fatalf("write second artifact: %v", err)
	}
	first, err := New(Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		Timeout: 5 * time.Second,
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := New(Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		ArtifactOverride: secondArtifact, Timeout: 5 * time.Second,
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	firstView, err := database.GetRun(context.Background(), first.RunID)
	if err != nil {
		t.Fatalf("first view: %v", err)
	}
	secondView, err := database.GetRun(context.Background(), second.RunID)
	if err != nil {
		t.Fatalf("second view: %v", err)
	}
	if firstView.ArtifactPath != firstArtifact {
		t.Fatalf("first artifact path = %q, want %q", firstView.ArtifactPath, firstArtifact)
	}
	if secondView.ArtifactPath != secondArtifact {
		t.Fatalf("second artifact path = %q, want %q", secondView.ArtifactPath, secondArtifact)
	}
}

func TestReportSeparatesAutomaticAndManual(t *testing.T) {
	parsed, database, evidenceStore := testHarness(t, successTargetScript())
	result, err := New(Options{
		Store: database, Evidence: evidenceStore, Manifest: parsed,
		Timeout: 5 * time.Second,
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	built, err := report.Build(context.Background(), database, evidenceStore, result.RunID)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !built.Automatic.EvidenceIntegrity.OK {
		t.Fatalf("integrity = %#v", built.Automatic.EvidenceIntegrity)
	}
	if built.Manual.Status != "pending" || built.Manual.Pending != 4 {
		t.Fatalf("manual = %#v", built.Manual)
	}
	if err := database.SetManualCheck(
		context.Background(), result.RunID, "INDEPENDENT_REPLAY",
		"confirmed", "", "",
	); err == nil {
		t.Fatal("expected owner validation error")
	}
	if err := database.SetManualCheck(
		context.Background(), result.RunID, "INDEPENDENT_REPLAY",
		"confirmed", "reviewer", "hash matched",
	); err != nil {
		t.Fatalf("SetManualCheck: %v", err)
	}
	updated, err := report.Build(context.Background(), database, evidenceStore, result.RunID)
	if err != nil {
		t.Fatalf("Build updated: %v", err)
	}
	if updated.Manual.Pending != 3 {
		t.Fatalf("manual pending = %d", updated.Manual.Pending)
	}
}

func testHarness(t *testing.T, target string) (manifest.Parsed, *store.Store, *evidence.Store) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("SEEDAUDIT1\next=hook.v2\nseed=0\n"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	targetPath := filepath.Join(root, "fake-target")
	if err := os.WriteFile(targetPath, []byte(target), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	raw, err := json.Marshal(map[string]any{
		"schema_version": 2,
		"recovery": map[string]any{
			"id": "test-recovery", "captured_at": "2026-11-22T00:00:00Z",
			"app_version": "test", "rng": map[string]any{
				"algorithm": "splitmix64", "seed": "0",
				"restored_seed": "0", "state_sha256": "abc",
			},
			"target": targetPath, "artifact": artifact,
		},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	parsed, err := manifest.Parse(raw, root)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	database, err := store.Open(filepath.Join(root, "audit.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	evidenceStore, err := evidence.New(filepath.Join(root, "evidence"))
	if err != nil {
		t.Fatalf("open evidence: %v", err)
	}
	return parsed, database, evidenceStore
}

func successTargetScript() string {
	return "#!/bin/sh\ncat > \"$SEED_AUDIT_TRACE\" <<'TRACE'\n" + successTrace +
		"TRACE\nprintf '%s\\n' '[seed-audit] level=warn source=seed_target message=zero_seed_after_recovery' >&2\n" +
		"printf '%s\\n' '[seed-audit] level=warn source=seed_target message=unknown_extension_denied' >&2\n"
}

func hasFinding(findings []model.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func hasAction(actions []model.NextAction, code string) bool {
	for _, action := range actions {
		if action.Code == code {
			return true
		}
	}
	return false
}

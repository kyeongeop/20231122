package replay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"seedreview/internal/evidence"
	"seedreview/internal/manifest"
	"seedreview/internal/store"
)

func TestActualLibFuzzerSuccessAndCrash(t *testing.T) {
	target := os.Getenv("SEEDREVIEW_LIBFUZZER_TARGET")
	if target == "" {
		target = filepath.Join("..", "..", "build", "seed_target")
	}
	target, _ = filepath.Abs(target)
	if _, err := os.Stat(target); err != nil {
		t.Skipf("libFuzzer target not built: %v", err)
	}
	successArtifact, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "artifacts", "unknown-ext.bin"))
	crashArtifact, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "artifacts", "crash-probe.bin"))

	t.Run("unknown extension is denied", func(t *testing.T) {
		parsed, database, evidenceStore := actualTargetHarness(t, target, successArtifact, "success")
		result, err := New(Options{
			Store: database, Evidence: evidenceStore, Manifest: parsed,
			Timeout: 10 * time.Second,
		}).Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if result.Status != "ok" || result.EffectiveSeed != "0" {
			t.Fatalf("result = %#v", result)
		}
		view, err := database.GetRun(context.Background(), result.RunID)
		if err != nil {
			t.Fatalf("GetRun: %v", err)
		}
		if view.AutoConclusion != "unknown_extension_denied" {
			t.Fatalf("conclusion = %q", view.AutoConclusion)
		}
		if len(view.Extensions) != 1 || view.Extensions[0].Trigger == nil {
			t.Fatalf("extensions = %#v", view.Extensions)
		}
		t.Logf("trace evidence=%s trigger=%s:%d",
			view.TraceEvidence, view.Extensions[0].Trigger.File,
			view.Extensions[0].Trigger.Line)
	})

	t.Run("crash keeps actionable evidence", func(t *testing.T) {
		parsed, database, evidenceStore := actualTargetHarness(t, target, crashArtifact, "crash")
		result, err := New(Options{
			Store: database, Evidence: evidenceStore, Manifest: parsed,
			Timeout: 10 * time.Second,
		}).Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if result.Status != "crash" || result.FailureCode != "replay_crash" {
			t.Fatalf("result = %#v", result)
		}
		if !hasAction(result.NextActions, "KEEP_CRASH_EVIDENCE") {
			t.Fatalf("actions = %#v", result.NextActions)
		}
	})
}

func actualTargetHarness(
	t *testing.T,
	target, artifact, name string,
) (manifest.Parsed, *store.Store, *evidence.Store) {
	t.Helper()
	root := t.TempDir()
	raw, err := json.Marshal(map[string]any{
		"schema_version": 2,
		"recovery": map[string]any{
			"id": "actual-" + name, "captured_at": "2026-11-22T00:00:00Z",
			"app_version": "test", "rng": map[string]any{
				"algorithm": "splitmix64", "seed": "0",
				"restored_seed": "0", "state_sha256": "abc",
			},
			"target": target, "artifact": artifact,
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

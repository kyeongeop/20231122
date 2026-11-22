package manifest

import (
	"path/filepath"
	"testing"
)

func TestParseLegacyFormat(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "recovery-v1.json")
	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	recovery := parsed.Recovery
	if recovery.SourceFormat != "legacy-v1" {
		t.Fatalf("SourceFormat = %q", recovery.SourceFormat)
	}
	if recovery.Seed != "0" || recovery.RecoveredSeed != "0" {
		t.Fatalf("unexpected seeds: %#v", recovery)
	}
	if recovery.RNGAlgorithm != "splitmix64" {
		t.Fatalf("RNGAlgorithm = %q", recovery.RNGAlgorithm)
	}
	if recovery.StateSHA256 == "" {
		t.Fatal("legacy state hash was not normalized")
	}
	if filepath.Base(recovery.Artifact) != "unknown-ext.bin" {
		t.Fatalf("Artifact = %q", recovery.Artifact)
	}
	if filepath.Base(recovery.Target) != "seed_target" {
		t.Fatalf("Target = %q", recovery.Target)
	}
}

func TestParseCanonicalV2Format(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "recovery-v2.json")
	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	recovery := parsed.Recovery
	if recovery.SourceFormat != "canonical-v2" {
		t.Fatalf("SourceFormat = %q", recovery.SourceFormat)
	}
	if recovery.RecoveryID != "rec-2026-11-22-0040" {
		t.Fatalf("RecoveryID = %q", recovery.RecoveryID)
	}
	if recovery.StateSHA256 == "" {
		t.Fatal("nested rng state hash was not normalized")
	}
	if recovery.Environment["SEED_AUDIT_RECOVERY_SEED"] != "0" {
		t.Fatalf("environment = %#v", recovery.Environment)
	}
	if parsed.Recovery.Key == "" || parsed.Recovery.Key == parsed.Recovery.RecoveryID {
		t.Fatalf("manifest key = %q", parsed.Recovery.Key)
	}
}

func TestParseRejectsMissingArtifact(t *testing.T) {
	raw := []byte(`{"schema_version":2,"recovery":{"target":"/tmp/target"}}`)
	if _, err := Parse(raw, "/tmp"); err == nil {
		t.Fatal("expected missing artifact error")
	}
}

package main

import (
	"path/filepath"
	"testing"
)

func TestCanonicalizationDivergesAtRootBoundary(t *testing.T) {
	decoded, err := decodeOnce(rawInput)
	if err != nil {
		t.Fatalf("decode input: %v", err)
	}
	if decoded != decodedInput {
		t.Fatalf("decoded = %q, want %q", decoded, decodedInput)
	}
	if got := legacyResolve(decoded); got != legacyOutput {
		t.Fatalf("legacy = %q, want %q", got, legacyOutput)
	}
	if got := hardenedResolve(decoded, "/srv/www"); got != hardenedOutput {
		t.Fatalf("hardened = %q, want %q", got, hardenedOutput)
	}
	if got := extensionOf(legacyOutput); got != ".unk9" {
		t.Fatalf("extension = %q, want .unk9", got)
	}
}

func TestReplayPersistsTraceWithoutOverwritingAutoFindings(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "case.db"), "TEST-CASE")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.db.Close()

	before, err := store.loadCaseDetail()
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	if before.Reviews == nil {
		t.Fatal("reviews must serialize as an empty array, not null")
	}
	if len(before.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(before.Findings))
	}

	result, err := store.replayRecovered()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !result.Diverged || !result.MatchedInput {
		t.Fatalf("unexpected replay result: %+v", result)
	}
	if result.LegacyPath != legacyOutput || result.HardenedPath != hardenedOutput {
		t.Fatalf("unexpected outputs: legacy=%q hardened=%q", result.LegacyPath, result.HardenedPath)
	}

	after, err := store.loadCaseDetail()
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(after.Replays) != len(before.Replays)+1 {
		t.Fatalf("replays = %d, want %d", len(after.Replays), len(before.Replays)+1)
	}
	if len(after.Steps) != len(before.Steps)+1 {
		t.Fatalf("steps = %d, want %d", len(after.Steps), len(before.Steps)+1)
	}
	if len(after.Findings) != len(before.Findings) {
		t.Fatal("automatic findings must not be overwritten by a replay")
	}

	if _, err := store.addReview("confirmed", "test-reviewer", "reproduced twice"); err != nil {
		t.Fatalf("add review: %v", err)
	}
	reviewed, err := store.loadCaseDetail()
	if err != nil {
		t.Fatalf("load reviewed: %v", err)
	}
	if len(reviewed.Reviews) != 1 {
		t.Fatalf("reviews = %d, want 1", len(reviewed.Reviews))
	}
	if reviewed.Case.Status != "confirmed" {
		t.Fatalf("case status = %q, want confirmed", reviewed.Case.Status)
	}
	if len(reviewed.Findings) != 2 {
		t.Fatal("manual review must not replace automatic findings")
	}
}

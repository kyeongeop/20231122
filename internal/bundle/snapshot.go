package bundle

import (
	"context"
	"fmt"
	"path/filepath"

	"auditfix/internal/db"
)

func verifySnapshot(ctx context.Context, root string, loaded loadedBundle) error {
	store, err := db.OpenReadOnly(filepath.Join(root, DatabaseName))
	if err != nil {
		return fmt.Errorf("open exported sqlite snapshot: %w", err)
	}
	defer store.Close()
	caseRow, err := store.GetCase(ctx, loaded.manifest.CaseID)
	if err != nil {
		return err
	}
	if !canonicalEqual(caseRow, loaded.caseRow) {
		return errorsNew("sqlite snapshot case row differs from case.json")
	}
	run, err := store.GetRun(ctx, loaded.manifest.RunID)
	if err != nil {
		return err
	}
	if !canonicalEqual(run, loaded.run) {
		return errorsNew("sqlite snapshot run row differs from run.json")
	}
	events, err := store.ListEvents(ctx, loaded.manifest.CaseID)
	if err != nil {
		return err
	}
	if !canonicalEqual(events, loaded.events) {
		return errorsNew("sqlite snapshot events differ from events.jsonl")
	}
	corrections, err := store.ListCorrections(ctx, loaded.manifest.CaseID)
	if err != nil {
		return err
	}
	if !canonicalEqual(corrections, loaded.corrections) {
		return errorsNew("sqlite snapshot corrections differ from corrections.jsonl")
	}
	evidence, err := store.ListEvidence(ctx, loaded.manifest.CaseID)
	if err != nil {
		return err
	}
	if len(evidence) != len(loaded.evidence) {
		return errorsNew("sqlite snapshot evidence row count differs")
	}
	for i, item := range evidence {
		row := loaded.evidence[i]
		if item.BlobID != row.BlobID || item.CaseID != row.CaseID ||
			item.Role != row.Role || item.SourceName != row.SourceName ||
			item.SHA256 != row.SHA256 || item.Size != row.Size {
			return errorsNew("sqlite snapshot evidence differs from evidence.jsonl")
		}
	}
	samples, err := store.ListSamples(ctx, loaded.manifest.CaseID)
	if err != nil {
		return err
	}
	if len(samples) != len(loaded.samples) {
		return errorsNew("sqlite snapshot sample row count differs")
	}
	names := make(map[string]string)
	for i, sample := range samples {
		row := loaded.samples[i]
		names[sample.SampleID] = sample.Name
		if sample.SampleID != row.SampleID || sample.CaseID != row.CaseID ||
			sample.SampleIndex != row.SampleIndex || sample.Name != row.Name ||
			sample.SHA256 != row.SHA256 || sample.Size != row.Size ||
			sample.SourceName != row.SourceName || sample.ImportedAt != row.ImportedAt {
			return errorsNew("sqlite snapshot samples differ from samples.jsonl")
		}
	}
	attempts, err := store.ListAttempts(ctx, loaded.manifest.RunID)
	if err != nil {
		return err
	}
	if len(attempts) != len(loaded.attempts) {
		return errorsNew("sqlite snapshot attempt row count differs")
	}
	for i, attempt := range attempts {
		row := loaded.attempts[i]
		if attempt.RunID != row.RunID || attempt.SampleID != row.SampleID ||
			attempt.SampleIndex != row.SampleIndex ||
			names[attempt.SampleID] != row.SampleName ||
			attempt.AttemptNo != row.AttemptNo || attempt.Status != row.Status ||
			attempt.StartedAt != row.StartedAt || attempt.FinishedAt != row.FinishedAt ||
			attempt.ExitCode != row.ExitCode || attempt.Signal != row.Signal ||
			attempt.TimedOut != row.TimedOut ||
			sha256Hex(attempt.Stdout) != row.StdoutSHA256 ||
			sha256Hex(attempt.Stderr) != row.StderrSHA256 ||
			attempt.StdoutSHA256 != row.StdoutSHA256 ||
			attempt.StderrSHA256 != row.StderrSHA256 ||
			attempt.HarnessOutput != row.HarnessOutput ||
			attempt.ResultJSON != row.ResultJSON || attempt.Error != row.Error ||
			attempt.EvidenceSHA256 != row.EvidenceSHA256 {
			return errorsNew("sqlite snapshot attempts differ from attempts.jsonl")
		}
	}
	return nil
}

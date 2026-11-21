package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"auditfix/internal/db"
	"auditfix/internal/model"
)

func Export(ctx context.Context, store *db.Store, runID, outDir string, force bool) (Manifest, error) {
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		return Manifest{}, err
	}
	caseRow, err := store.GetCase(ctx, run.CaseID)
	if err != nil {
		return Manifest{}, err
	}
	events, err := store.ListEvents(ctx, run.CaseID)
	if err != nil {
		return Manifest{}, err
	}
	corrections, err := store.ListCorrections(ctx, run.CaseID)
	if err != nil {
		return Manifest{}, err
	}
	evidence, err := store.ListEvidence(ctx, run.CaseID)
	if err != nil {
		return Manifest{}, err
	}
	samples, err := store.ListSamples(ctx, run.CaseID)
	if err != nil {
		return Manifest{}, err
	}
	attempts, err := store.ListAttempts(ctx, runID)
	if err != nil {
		return Manifest{}, err
	}

	absolute, err := filepath.Abs(outDir)
	if err != nil {
		return Manifest{}, err
	}
	if info, err := os.Stat(absolute); err == nil && !force {
		return Manifest{}, fmt.Errorf("output %q already exists (%s)", outDir, info.Mode())
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return Manifest{}, err
	}
	tempDir, err := os.MkdirTemp(filepath.Dir(absolute), ".auditfix-export-*")
	if err != nil {
		return Manifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tempDir)
		}
	}()

	if err := writeCanonical(filepath.Join(tempDir, "case.json"), caseRow); err != nil {
		return Manifest{}, err
	}
	if err := writeCanonical(filepath.Join(tempDir, "run.json"), run); err != nil {
		return Manifest{}, err
	}
	if err := writeJSONL(filepath.Join(tempDir, "events.jsonl"), toAny(events)); err != nil {
		return Manifest{}, err
	}
	if err := writeJSONL(filepath.Join(tempDir, "corrections.jsonl"), toAny(corrections)); err != nil {
		return Manifest{}, err
	}

	var evidenceRows []EvidenceRow
	for _, item := range evidence {
		data, err := store.GetEvidenceBytes(ctx, item.BlobID)
		if err != nil {
			return Manifest{}, err
		}
		path := fmt.Sprintf("evidence/%04d-%s-%s.blob", item.BlobID, item.Role, item.SHA256[:12])
		if err := os.MkdirAll(filepath.Join(tempDir, "evidence"), 0o755); err != nil {
			return Manifest{}, err
		}
		if err := os.WriteFile(filepath.Join(tempDir, path), data, 0o644); err != nil {
			return Manifest{}, err
		}
		evidenceRows = append(evidenceRows, EvidenceRow{
			BlobID: item.BlobID, CaseID: item.CaseID, Role: item.Role,
			SourceName: item.SourceName, SHA256: item.SHA256,
			Size: item.Size, BundlePath: path,
		})
	}
	if err := writeJSONL(filepath.Join(tempDir, "evidence.jsonl"),
		toAny(evidenceRows)); err != nil {
		return Manifest{}, err
	}

	var sampleRows []SampleRow
	sampleNames := make(map[string]string)
	for _, sample := range samples {
		_, data, err := store.FindSample(ctx, run.CaseID, sample.SampleID)
		if err != nil {
			return Manifest{}, err
		}
		path := fmt.Sprintf("samples/%04d-%s.sample", sample.SampleIndex, sample.SHA256)
		if err := os.MkdirAll(filepath.Join(tempDir, "samples"), 0o755); err != nil {
			return Manifest{}, err
		}
		if err := os.WriteFile(filepath.Join(tempDir, path), data, 0o644); err != nil {
			return Manifest{}, err
		}
		sampleRows = append(sampleRows, modelSampleToRow(sample, path))
		sampleNames[sample.SampleID] = sample.Name
	}
	if err := writeJSONL(filepath.Join(tempDir, "samples.jsonl"),
		toAny(sampleRows)); err != nil {
		return Manifest{}, err
	}

	attemptRows := make([]AttemptRow, 0, len(attempts))
	for _, attempt := range attempts {
		stdoutPath := fmt.Sprintf("attempts/%04d-%04d.stdout",
			attempt.SampleIndex, attempt.AttemptNo)
		stderrPath := fmt.Sprintf("attempts/%04d-%04d.stderr",
			attempt.SampleIndex, attempt.AttemptNo)
		if err := os.MkdirAll(filepath.Join(tempDir, "attempts"), 0o755); err != nil {
			return Manifest{}, err
		}
		if err := os.WriteFile(filepath.Join(tempDir, stdoutPath), attempt.Stdout, 0o644); err != nil {
			return Manifest{}, err
		}
		if err := os.WriteFile(filepath.Join(tempDir, stderrPath), attempt.Stderr, 0o644); err != nil {
			return Manifest{}, err
		}
		attemptRows = append(attemptRows, AttemptRow{
			RunID: attempt.RunID, SampleID: attempt.SampleID,
			SampleIndex: attempt.SampleIndex, SampleName: sampleNames[attempt.SampleID],
			AttemptNo: attempt.AttemptNo, Status: attempt.Status,
			StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt,
			ExitCode: attempt.ExitCode, Signal: attempt.Signal,
			TimedOut: attempt.TimedOut, StdoutSHA256: attempt.StdoutSHA256,
			StderrSHA256: attempt.StderrSHA256, StdoutPath: stdoutPath,
			StderrPath:    stderrPath,
			HarnessOutput: attempt.HarnessOutput, ResultJSON: attempt.ResultJSON,
			Error: attempt.Error, EvidenceSHA256: attempt.EvidenceSHA256,
		})
	}
	if err := writeJSONL(filepath.Join(tempDir, "attempts.jsonl"),
		toAny(attemptRows)); err != nil {
		return Manifest{}, err
	}
	if err := writeReview(filepath.Join(tempDir, "review.md"), caseRow, run,
		corrections, sampleRows, attemptRows); err != nil {
		return Manifest{}, err
	}

	dbPath := filepath.Join(tempDir, DatabaseName)
	if err := snapshotDatabase(ctx, store, dbPath); err != nil {
		return Manifest{}, err
	}
	dbSHA, dbSize, err := sha256File(dbPath)
	if err != nil {
		return Manifest{}, err
	}
	files, err := collectFiles(tempDir, DatabaseName)
	if err != nil {
		return Manifest{}, err
	}
	exportedAt := run.FinishedAt
	if exportedAt == "" {
		exportedAt = run.CreatedAt
	}
	manifest := Manifest{
		Schema: FormatSchema, ToolVersion: model.ToolVersion,
		SQLiteSchema: model.SchemaVersion, CaseID: run.CaseID, RunID: run.RunID,
		RunStatus: run.Status, ExportedAt: exportedAt,
		HarnessSHA256: run.HarnessSHA256, HarnessPath: run.HarnessPath,
		TimeoutMS: run.TimeoutMS, FuzzArgs: run.FuzzArgs,
		FieldOrders: expectedFieldOrders(),
		RowCounts: RowCounts{
			Events: len(events), Corrections: len(corrections),
			Evidence: len(evidenceRows), Samples: len(sampleRows),
			Attempts: len(attemptRows),
		},
		Files:    files,
		Database: FileEntry{Path: DatabaseName, SHA256: dbSHA, Size: dbSize},
		ReviewNotes: []string{
			"Original logs and sample bytes are embedded; correction rows annotate gaps and never synthesize missing events.",
			"JSONL rows are canonical and ordered; verify recomputes every file and row-field digest.",
			"Attempt evidence digest binds sample hash, harness hash, result fields, and captured output hashes.",
			"Use 'auditfix verify --rerun --harness PATH' to independently reproduce each sample.",
		},
	}
	if err := writeCanonical(filepath.Join(tempDir, ManifestName), manifest); err != nil {
		return Manifest{}, err
	}
	manifestPath := filepath.Join(tempDir, ManifestName)
	manifestSHA, _, err := sha256File(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(tempDir, DigestName),
		[]byte(manifestSHA+"  "+ManifestName+"\n"), 0o644); err != nil {
		return Manifest{}, err
	}

	backup := ""
	if _, err := os.Stat(absolute); err == nil {
		backup = absolute + ".auditfix-old"
		_ = os.RemoveAll(backup)
		if err := os.Rename(absolute, backup); err != nil {
			return Manifest{}, err
		}
	}
	if err := os.Rename(tempDir, absolute); err != nil {
		if backup != "" {
			_ = os.Rename(backup, absolute)
		}
		return Manifest{}, err
	}
	committed = true
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	return manifest, nil
}

func toAny[T any](values []T) []any {
	out := make([]any, len(values))
	for i := range values {
		out[i] = values[i]
	}
	return out
}

func writeReview(path string, c model.Case, run model.Run,
	corrections []model.Correction, samples []SampleRow, attempts []AttemptRow) error {
	var b strings.Builder
	b.WriteString("# Security audit log integrity review\n\n")
	fmt.Fprintf(&b, "- Case: `%s`\n", c.CaseID)
	fmt.Fprintf(&b, "- Run: `%s` (%s)\n", run.RunID, run.Status)
	fmt.Fprintf(&b, "- Chain status: `%s`\n", c.ChainStatus)
	fmt.Fprintf(&b, "- Clock offset applied to device-b: `%d ns`\n", c.ClockOffsetNS)
	fmt.Fprintf(&b, "- Shared anchor pairs: `%d`\n", c.AnchorPairCount)
	fmt.Fprintf(&b, "- Missing segments annotated: `%d`\n\n", len(corrections))
	b.WriteString("## Missing segments\n\n")
	if len(corrections) == 0 {
		b.WriteString("No sequence gaps were observed.\n\n")
	} else {
		b.WriteString("| Device | Missing seq | Left hash | Right prev hash | Rationale |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, corr := range corrections {
			fmt.Fprintf(&b, "| %s | %d-%d | `%s` | `%s` | `%s` |\n",
				corr.Device, corr.SeqFrom, corr.SeqTo, corr.LeftHash,
				corr.RightPrevHash, corr.RationaleCode)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Samples and attempts\n\n")
	b.WriteString("| # | Sample | SHA-256 | Attempts | Latest classification |\n")
	b.WriteString("|---|---|---|---|---|\n")
	latest := make(map[string]AttemptRow)
	counts := make(map[string]int)
	for _, attempt := range attempts {
		counts[attempt.SampleID]++
		if isTerminal(attempt.Status) {
			latest[attempt.SampleID] = attempt
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].SampleIndex < samples[j].SampleIndex })
	for _, sample := range samples {
		class := "-"
		if attempt, ok := latest[sample.SampleID]; ok {
			class = classification(attempt.ResultJSON)
		}
		fmt.Fprintf(&b, "| %d | `%s` | `%s` | %d | `%s` |\n",
			sample.SampleIndex, sample.Name, sample.SHA256,
			counts[sample.SampleID], class)
	}
	b.WriteString("\n## Independent review\n\n")
	b.WriteString("1. Run `auditfix verify --bundle .` to check the detached manifest digest, every file digest, canonical field order, row ordering, sample bytes, and attempt evidence digests.\n")
	b.WriteString("2. Compare `events.jsonl` with the original blobs in `evidence/`; `corrections.jsonl` is an annotation and does not replace source records.\n")
	b.WriteString("3. Optionally run `auditfix verify --bundle . --rerun --harness /path/to/auditfix_fuzz` to execute every embedded sample again.\n")
	b.WriteString("4. Restore the exact SQLite state with `auditfix restore --bundle . --db restored.sqlite`.\n")
	b.WriteString("\nThis bundle is self-contained except for the libFuzzer executable used by optional reruns.\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func isTerminal(status string) bool {
	return status == "complete" || status == "crash" || status == "timeout"
}

func classification(resultJSON string) string {
	const key = `"classification":"`
	idx := strings.Index(resultJSON, key)
	if idx < 0 {
		return "UNKNOWN"
	}
	rest := resultJSON[idx+len(key):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "UNKNOWN"
	}
	return rest[:end]
}

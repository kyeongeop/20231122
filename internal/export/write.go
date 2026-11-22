package export

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
	"taintlab/internal/store"
)

func WriteDir(dir string, runs []store.StoredRun, options Options) (Manifest, error) {
	var manifest Manifest
	if dir == "" {
		return manifest, fmt.Errorf("export directory is empty")
	}
	if options.ExportedAt == "" {
		options.ExportedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, options.ExportedAt); err != nil {
		return manifest, fmt.Errorf("exported_at is not RFC3339: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return manifest, fmt.Errorf("create export directory: %w", err)
	}

	recordsPath := filepath.Join(dir, "records.jsonl")
	eventsPath := filepath.Join(dir, "evidence.jsonl")
	readmePath := filepath.Join(dir, "README.txt")
	eventCount, err := writeRecords(recordsPath, eventsPath, runs)
	if err != nil {
		return manifest, err
	}
	if err := os.WriteFile(readmePath, []byte(reviewReadme), 0o644); err != nil {
		return manifest, fmt.Errorf("write review README: %w", err)
	}
	for _, name := range []string{"records.jsonl", "evidence.jsonl", "README.txt"} {
		digest, err := digestFile(filepath.Join(dir, name))
		if err != nil {
			return manifest, err
		}
		manifest.Files = append(manifest.Files, digest)
	}
	manifest.Format = model.ExportSchema
	manifest.ToolVersion = ToolVersion
	manifest.ExportedAt = options.ExportedAt
	manifest.RunCount = len(runs)
	manifest.EventCount = eventCount
	manifest.Ordering = "runs by run_id ASC; events by run_id ASC then event ordinal ASC"
	if err := writeManifest(filepath.Join(dir, "manifest.json"), manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func writeRecords(recordsPath, eventsPath string, runs []store.StoredRun) (int, error) {
	recordsFile, err := os.Create(recordsPath)
	if err != nil {
		return 0, fmt.Errorf("create records: %w", err)
	}
	defer recordsFile.Close()
	eventsFile, err := os.Create(eventsPath)
	if err != nil {
		return 0, fmt.Errorf("create evidence: %w", err)
	}
	defer eventsFile.Close()
	recordsWriter := bufio.NewWriter(recordsFile)
	eventsWriter := bufio.NewWriter(eventsFile)
	defer recordsWriter.Flush()
	defer eventsWriter.Flush()

	eventCount := 0
	for _, run := range runs {
		record := Record{
			RecordSchema: RecordSchema,
			RunID:        run.RunID,
			CreatedAt:    run.CreatedAt,
			CaseID:       run.Result.CaseID,
			TraceID:      run.Result.TraceID,
			InputSHA256:  run.Result.Input.SHA256,
			ResultSHA256: run.ResultSHA256,
			Result:       run.Result,
		}
		record.RecordSHA256 = recordDigest(record)
		line, err := canonical.JSON(record)
		if err != nil {
			return 0, fmt.Errorf("encode record %d: %w", run.RunID, err)
		}
		if _, err := recordsWriter.Write(append(line, '\n')); err != nil {
			return 0, fmt.Errorf("write record %d: %w", run.RunID, err)
		}
		for _, event := range run.Result.Evidence.Events {
			eventRecord := EventRecord{
				RecordSchema:  EventSchema,
				RunID:         run.RunID,
				CaseID:        run.Result.CaseID,
				TraceID:       run.Result.TraceID,
				EventOrdinal:  event.Ordinal,
				EventID:       event.EventID,
				DeviceID:      event.DeviceID,
				Kind:          event.Kind,
				CausalOrder:   event.CausalOrder,
				WallTime:      event.WallTime,
				MonotonicNS:   event.MonotonicNS,
				PayloadSHA256: event.PayloadSHA256,
				Detail:        event.Detail,
			}
			eventRecord.RecordSHA256 = eventDigest(eventRecord)
			line, err := canonical.JSON(eventRecord)
			if err != nil {
				return 0, fmt.Errorf("encode event %s: %w", event.EventID, err)
			}
			if _, err := eventsWriter.Write(append(line, '\n')); err != nil {
				return 0, fmt.Errorf("write event %s: %w", event.EventID, err)
			}
			eventCount++
		}
	}
	if err := recordsWriter.Flush(); err != nil {
		return 0, fmt.Errorf("flush records: %w", err)
	}
	if err := eventsWriter.Flush(); err != nil {
		return 0, fmt.Errorf("flush evidence: %w", err)
	}
	return eventCount, nil
}

func recordDigest(record Record) string {
	record.RecordSHA256 = ""
	return canonical.Sum(record)
}

func eventDigest(event EventRecord) string {
	event.RecordSHA256 = ""
	return canonical.Sum(event)
}

func digestFile(path string) (FileDigest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileDigest{}, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return FileDigest{
		Name:   filepath.Base(path),
		Bytes:  int64(len(data)),
		SHA256: canonical.SumBytes(data),
	}, nil
}

func writeManifest(path string, manifest Manifest) error {
	data, err := canonical.JSONIndent(manifest)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

const reviewReadme = `TaintLab evidence package

Verify this package without trusting the producer:

  taintlab verify-export --dir .

Files:
  records.jsonl    One self-hashed result record per run, ordered by run_id.
  evidence.jsonl   One self-hashed event record per evidence event.
  manifest.json    Field/file digests, counts, and the declared ordering.

Review rules:
  1. record_sha256 covers the record with record_sha256 set to "".
  2. result_sha256 covers the canonical JSON in the nested result field.
  3. Complete raw inputs are retained as hexadecimal in
     result.input.raw_hex and can be replayed byte-for-byte.
  4. Oversized inputs are intentionally incomplete: the full SHA-256,
     byte count, and first 256 bytes remain; raw_hex is empty.
  5. Do not sort events by wall_time. Ordering is causal_order/ordinal,
     because the scenario deliberately contains unsynchronized device clocks.
`

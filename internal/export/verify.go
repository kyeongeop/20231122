package export

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
	"taintlab/internal/taint"
)

func VerifyDir(dir string) (Verification, error) {
	var verification Verification
	manifestData, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return verification, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return verification, fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.Format != model.ExportSchema {
		return verification, fmt.Errorf("unsupported export format %q", manifest.Format)
	}
	if err := verifyManifestFiles(dir, manifest); err != nil {
		return verification, err
	}
	recordLines, err := readJSONLines(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		return verification, err
	}
	eventLines, err := readJSONLines(filepath.Join(dir, "evidence.jsonl"))
	if err != nil {
		return verification, err
	}
	if len(recordLines) != manifest.RunCount {
		return verification, fmt.Errorf("manifest run_count=%d, records=%d",
			manifest.RunCount, len(recordLines))
	}
	if len(eventLines) != manifest.EventCount {
		return verification, fmt.Errorf("manifest event_count=%d, events=%d",
			manifest.EventCount, len(eventLines))
	}

	records := make([]Record, 0, len(recordLines))
	eventCursor := 0
	previousRunID := int64(0)
	for index, line := range recordLines {
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return verification, fmt.Errorf("decode record %d: %w", index+1, err)
		}
		if record.RecordSchema != RecordSchema {
			return verification, fmt.Errorf("record %d has schema %q", index+1, record.RecordSchema)
		}
		if lineCanonical, err := canonical.JSON(record); err != nil ||
			!bytes.Equal(line, lineCanonical) {
			return verification, fmt.Errorf("record %d field order/unknown fields changed", index+1)
		}
		if got := recordDigest(record); got != record.RecordSHA256 {
			return verification, fmt.Errorf("record %d digest mismatch: got %s want %s",
				index+1, got, record.RecordSHA256)
		}
		if record.RunID <= previousRunID {
			return verification, fmt.Errorf("record run_id order is not ascending at %d", index+1)
		}
		previousRunID = record.RunID
		resultJSON, err := canonical.JSON(record.Result)
		if err != nil {
			return verification, fmt.Errorf("record %d result encode: %w", index+1, err)
		}
		if got := canonical.SumBytes(resultJSON); got != record.ResultSHA256 {
			return verification, fmt.Errorf("record %d result digest mismatch", index+1)
		}
		if record.InputSHA256 != record.Result.Input.SHA256 {
			return verification, fmt.Errorf("record %d input digest mismatch", index+1)
		}

		if record.Result.Input.RawComplete {
			raw, err := hex.DecodeString(record.Result.Input.RawHex)
			if err != nil {
				return verification, fmt.Errorf("record %d raw_hex: %w", index+1, err)
			}
			if len(raw) != record.Result.Input.SizeBytes ||
				canonical.SumBytes(raw) != record.Result.Input.SHA256 {
				return verification, fmt.Errorf("record %d raw input digest/size mismatch", index+1)
			}
			replayed := taint.Execute(raw)
			replayedJSON, err := canonical.JSON(replayed)
			if err != nil {
				return verification, fmt.Errorf("record %d replay encode: %w", index+1, err)
			}
			if got := canonical.SumBytes(replayedJSON); got != record.ResultSHA256 {
				return verification, fmt.Errorf("record %d replay result mismatch", index+1)
			}
			verification.ReplayedRuns++
		} else {
			verification.IncompleteRuns++
		}

		for _, expected := range record.Result.Evidence.Events {
			if eventCursor >= len(eventLines) {
				return verification, fmt.Errorf("record %d is missing event %s",
					index+1, expected.EventID)
			}
			if err := verifyEventLine(eventLines[eventCursor], record, expected); err != nil {
				return verification, fmt.Errorf("record %d: %w", index+1, err)
			}
			eventCursor++
		}
		records = append(records, record)
	}
	if eventCursor != len(eventLines) {
		return verification, fmt.Errorf("%d extra event records", len(eventLines)-eventCursor)
	}
	verification.Runs = len(records)
	verification.Events = len(eventLines)
	return verification, nil
}

func verifyEventLine(line []byte, record Record, expected model.LogEvent) error {
	var event EventRecord
	if err := json.Unmarshal(line, &event); err != nil {
		return fmt.Errorf("decode event %s: %w", expected.EventID, err)
	}
	if event.RecordSchema != EventSchema {
		return fmt.Errorf("event %s has schema %q", expected.EventID, event.RecordSchema)
	}
	if lineCanonical, err := canonical.JSON(event); err != nil ||
		!bytes.Equal(line, lineCanonical) {
		return fmt.Errorf("event %s field order/unknown fields changed", expected.EventID)
	}
	if got := eventDigest(event); got != event.RecordSHA256 {
		return fmt.Errorf("event %s digest mismatch", expected.EventID)
	}
	expectedRecord := EventRecord{
		RecordSchema:  EventSchema,
		RunID:         record.RunID,
		CaseID:        record.CaseID,
		TraceID:       record.TraceID,
		EventOrdinal:  expected.Ordinal,
		EventID:       expected.EventID,
		DeviceID:      expected.DeviceID,
		Kind:          expected.Kind,
		CausalOrder:   expected.CausalOrder,
		WallTime:      expected.WallTime,
		MonotonicNS:   expected.MonotonicNS,
		PayloadSHA256: expected.PayloadSHA256,
		Detail:        expected.Detail,
		RecordSHA256:  event.RecordSHA256,
	}
	if event != expectedRecord {
		return fmt.Errorf("event %s content/order differs from result JSON", expected.EventID)
	}
	return nil
}

func verifyManifestFiles(dir string, manifest Manifest) error {
	required := map[string]bool{
		"records.jsonl":  false,
		"evidence.jsonl": false,
		"README.txt":     false,
	}
	for _, file := range manifest.Files {
		if _, ok := required[file.Name]; ok {
			required[file.Name] = true
		}
		digest, err := digestFile(filepath.Join(dir, file.Name))
		if err != nil {
			return err
		}
		if digest.Bytes != file.Bytes || digest.SHA256 != file.SHA256 {
			return fmt.Errorf("manifest digest mismatch for %s", file.Name)
		}
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("manifest is missing %s", name)
		}
	}
	return nil
}

func readJSONLines(path string) ([][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lines := make([][]byte, 0)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lines = append(lines, append([]byte(nil), line...))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return lines, nil
}

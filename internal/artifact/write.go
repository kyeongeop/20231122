package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"corpusd/internal/model"
	"corpusd/internal/store"
)

const (
	recordsFile     = "records.jsonl"
	checkpointsFile = "checkpoints.jsonl"
	eventsFile      = "events.jsonl"
	comparisonsFile = "comparisons.jsonl"
	manifestFile    = "manifest.json"
	sumsFile        = "SHA256SUMS"
	readmeFile      = "README.md"
)

func WriteExport(st *store.Store, runID, dir string) (Manifest, error) {
	var manifest Manifest
	run, ok, err := st.Run(runID)
	if err != nil {
		return manifest, err
	}
	if !ok {
		return manifest, fmt.Errorf("run %q not found", runID)
	}
	if run.Status == "running" {
		return manifest, fmt.Errorf("run %q is still running; pause or finish it first", runID)
	}
	records, err := st.Results(runID, 0)
	if err != nil {
		return manifest, err
	}
	if len(records) == 0 {
		return manifest, fmt.Errorf("run %q has no records to export", runID)
	}
	checkpoints, err := st.Checkpoints(runID)
	if err != nil {
		return manifest, err
	}
	events, err := st.Events(runID)
	if err != nil {
		return manifest, err
	}
	comparisons, err := st.Comparisons(runID)
	if err != nil {
		return manifest, err
	}
	if err := prepareDir(dir); err != nil {
		return manifest, err
	}

	files := make([]FileEntry, 0, 8)
	recordHash, recordBytes, err := writeRecords(dir, records)
	if err != nil {
		return manifest, err
	}
	files = append(files, FileEntry{Name: recordsFile, SHA256: recordHash, Bytes: recordBytes})
	for _, item := range []struct {
		name string
		data [][]byte
	}{
		{checkpointsFile, marshalCheckpoints(checkpoints)},
		{eventsFile, marshalEvents(events)},
		{comparisonsFile, marshalComparisons(comparisons)},
	} {
		hash, size, err := writeLines(dir, item.name, item.data)
		if err != nil {
			return manifest, err
		}
		files = append(files, FileEntry{Name: item.name, SHA256: hash, Bytes: size})
	}

	inputs, inputFiles, err := copyInputs(dir, run.CorpusDir, records)
	if err != nil {
		return manifest, err
	}
	files = append(files, inputFiles...)
	readme := exportReadme(runID, run.Status)
	readmeHash, readmeBytes, err := writeBytes(dir, readmeFile, []byte(readme))
	if err != nil {
		return manifest, err
	}
	files = append(files, FileEntry{Name: readmeFile, SHA256: readmeHash, Bytes: readmeBytes})
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	allMatch := true
	for _, c := range comparisons {
		if !c.Match {
			allMatch = false
		}
	}
	finalized := run.Status == "completed" || run.Status == "completed_degraded"
	manifest = Manifest{
		Schema: model.ExportSchema, RecordType: "corpus_export",
		Generator: Generator, RunID: runID, Status: run.Status,
		ExportedTS: model.NowUTC(), CorpusFingerprint: run.CorpusFingerprint,
		RecordFields: model.RecordFields, ObservationFields: model.ObservationFields,
		AnalysisFields: model.AnalysisFields, EvidenceFields: model.EvidenceFields,
		RecordCount: len(records), CheckpointCount: len(checkpoints),
		EventCount: len(events), ComparisonCount: len(comparisons),
		InputCount: len(inputs), ResultDigest: model.ResultDigest(records),
		RecordsSHA256: recordHash, ComparisonsPass: allMatch,
		Finalized: finalized, Files: files, Inputs: inputs,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	manifestData = append(manifestData, '\n')
	if err := CheckOrder(manifestData, ManifestFields); err != nil {
		return manifest, fmt.Errorf("manifest field order: %w", err)
	}
	manifestHash, manifestBytes, err := writeBytes(dir, manifestFile, manifestData)
	if err != nil {
		return manifest, err
	}
	allFiles := append(append([]FileEntry(nil), files...),
		FileEntry{Name: manifestFile, SHA256: manifestHash, Bytes: manifestBytes})
	if err := writeSums(dir, allFiles); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("export directory %q is not empty", dir)
	}
	return nil
}

func writeRecords(dir string, records []model.Record) (string, int64, error) {
	lines := make([][]byte, 0, len(records))
	for _, rec := range records {
		data, err := model.MarshalRecord(rec)
		if err != nil {
			return "", 0, err
		}
		if err := CheckOrder(data, model.RecordFields); err != nil {
			return "", 0, fmt.Errorf("record %d field order: %w", rec.Seq, err)
		}
		lines = append(lines, data)
	}
	return writeLines(dir, recordsFile, lines)
}

func marshalCheckpoints(items []model.Checkpoint) [][]byte {
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		data, _ := model.MarshalCheckpoint(item)
		out = append(out, data)
	}
	return out
}

func marshalEvents(items []model.Event) [][]byte {
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		data, _ := model.MarshalEvent(item)
		out = append(out, data)
	}
	return out
}

func marshalComparisons(items []model.Comparison) [][]byte {
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		data, _ := model.MarshalComparison(item)
		out = append(out, data)
	}
	return out
}

func writeLines(dir, name string, lines [][]byte) (string, int64, error) {
	var buf []byte
	for _, line := range lines {
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return writeBytes(dir, name, buf)
}

func writeBytes(dir, name string, data []byte) (string, int64, error) {
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

func copyInputs(dir, corpusDir string, records []model.Record) ([]InputFile, []FileEntry, error) {
	var inputs []InputFile
	var files []FileEntry
	for _, rec := range records {
		rel, err := safeRel(rec.InputName)
		if err != nil {
			return nil, nil, err
		}
		exportName := filepath.ToSlash(filepath.Join("inputs", rel))
		srcPath := filepath.Join(corpusDir, filepath.FromSlash(rel))
		dstPath := filepath.Join(dir, "inputs", filepath.FromSlash(rel))
		if err := copyFile(srcPath, dstPath); err != nil {
			return nil, nil, fmt.Errorf("copy input %s: %w", rec.InputName, err)
		}
		sha, size, err := hashFile(dstPath)
		if err != nil {
			return nil, nil, err
		}
		if sha != rec.InputSHA256 || size != rec.InputBytes {
			return nil, nil, fmt.Errorf("exported input %s does not match record %d",
				rec.InputName, rec.Seq)
		}
		inputs = append(inputs, InputFile{
			Seq: rec.Seq, Name: exportName, SHA256: sha, Bytes: size,
		})
		files = append(files, FileEntry{Name: exportName, SHA256: sha, Bytes: size})
	}
	return inputs, files, nil
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func safeRel(name string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
		strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe artifact path %q", name)
	}
	return clean, nil
}

func writeSums(dir string, files []FileEntry) error {
	sorted := append([]FileEntry(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, f := range sorted {
		fmt.Fprintf(&b, "%s  %s\n", f.SHA256, f.Name)
	}
	_, _, err := writeBytes(dir, sumsFile, []byte(b.String()))
	return err
}

func exportReadme(runID, status string) string {
	return fmt.Sprintf(`# Fuzz corpus evidence export

Run ID: %s
Status: %s

This directory is self-contained evidence. It does not require SQLite or the
original corpus to verify.

Files:
- records.jsonl: one canonical corpus-object record per line, in seq order.
- checkpoints.jsonl: resumable cursor/state snapshots.
- events.jsonl: pause, resume, degradation, comparison, and completion evidence.
- comparisons.jsonl: checkpoint restore and final recomputation results.
- manifest.json: schema, counts, field order, and digest of every file.
- inputs/: immutable copies of every corpus input, addressed by input_name.

Field order is part of the schema. Each record starts with:
schema, record_type, run_id, seq, object_id, input_name, input_sha256,
input_bytes, observations, canonical_device, canonical_ts_ns, duplicate,
duplicate_of_seq, mode, degraded_reason, decision, analysis, evidence.

Independent checks:
1. Verify SHA-256 in manifest.json against each file.
2. Verify object_id == "sha256:" + input_sha256 and hash the matching input.
3. Verify corrected_ts_ns == raw_ts_ns - clock_offset_ns.
4. Verify seq is contiguous and records.jsonl sequence hash equals
   manifest.result_digest.
5. Verify comparisons_pass and, for finalized runs, final_recompute match=true.

The corpusctl verify-export command performs these checks without opening SQLite.
`, runID, status)
}

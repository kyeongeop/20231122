package artifact

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"corpusd/internal/model"
)

func verifyRecords(dir string, m *Manifest, records []model.Record) error {
	if len(m.Inputs) != len(records) {
		return fmt.Errorf("input snapshot count: manifest=%d records=%d",
			len(m.Inputs), len(records))
	}
	firstSeen := make(map[string]int64)
	modes := make(map[string]string)
	seenInputs := make(map[string]bool)
	globallyDegraded := false
	for i, rec := range records {
		if rec.Schema != model.SchemaVersion || rec.RecordType != model.RecordType {
			return fmt.Errorf("record %d identity mismatch", rec.Seq)
		}
		if rec.RunID != m.RunID {
			return fmt.Errorf("record %d run id %q != %q", rec.Seq, rec.RunID, m.RunID)
		}
		if rec.Seq != int64(i+1) {
			return fmt.Errorf("record order: index %d has seq %d", i+1, rec.Seq)
		}
		if seenInputs[rec.InputName] {
			return fmt.Errorf("duplicate input_name %q", rec.InputName)
		}
		seenInputs[rec.InputName] = true
		if err := verifyRecord(rec, firstSeen, modes, &globallyDegraded); err != nil {
			return fmt.Errorf("record %d: %w", rec.Seq, err)
		}
		input := m.Inputs[i]
		if err := verifyInput(dir, rec, input); err != nil {
			return fmt.Errorf("record %d input: %w", rec.Seq, err)
		}
	}
	return nil
}

func verifyRecord(rec model.Record, firstSeen map[string]int64, modes map[string]string, globallyDegraded *bool) error {
	if !validSHA(rec.InputSHA256) {
		return fmt.Errorf("invalid input_sha256 %q", rec.InputSHA256)
	}
	if rec.ObjectID != model.ObjectID(rec.InputSHA256) {
		return fmt.Errorf("object_id does not match input hash")
	}
	if rec.InputBytes < 0 || rec.Evidence.CorpusIndex != rec.Seq ||
		rec.Evidence.SourcePath != rec.InputName {
		return fmt.Errorf("corpus evidence does not match record identity")
	}
	first, duplicate := firstSeen[rec.ObjectID]
	if duplicate != rec.Duplicate {
		return fmt.Errorf("duplicate flag=%t but prior object=%t", rec.Duplicate, duplicate)
	}
	if duplicate {
		if rec.DuplicateOfSeq != first || rec.Evidence.FirstSeenSeq != first {
			return fmt.Errorf("duplicate reference want %d got %d/%d",
				first, rec.DuplicateOfSeq, rec.Evidence.FirstSeenSeq)
		}
		if rec.Evidence.AnalysisReused && rec.Evidence.ReusedFromSeq != first {
			return fmt.Errorf("reused analysis must reference first seq %d", first)
		}
		if !rec.Evidence.AnalysisReused && rec.Evidence.ReusedFromSeq != 0 {
			return fmt.Errorf("non-reused duplicate has reused_from_seq %d",
				rec.Evidence.ReusedFromSeq)
		}
	} else {
		if rec.DuplicateOfSeq != 0 || rec.Evidence.FirstSeenSeq != rec.Seq {
			return fmt.Errorf("first occurrence has invalid duplicate evidence")
		}
		if rec.Evidence.AnalysisReused || rec.Evidence.ReusedFromSeq != 0 {
			return fmt.Errorf("first occurrence cannot reuse analysis")
		}
		firstSeen[rec.ObjectID] = rec.Seq
	}
	if priorMode, ok := modes[rec.ObjectID]; ok && priorMode == model.ModeDegraded &&
		rec.Mode == model.ModeFull {
		return fmt.Errorf("mode recovered from degraded to full")
	}
	if *globallyDegraded && rec.Mode == model.ModeFull {
		return fmt.Errorf("run recovered from degraded to full")
	}
	*globallyDegraded = *globallyDegraded || rec.Mode == model.ModeDegraded
	modes[rec.ObjectID] = rec.Mode

	if err := verifyClocks(rec); err != nil {
		return err
	}
	if err := verifyAnalysis(rec); err != nil {
		return err
	}
	if rec.Evidence.MemoryBudgetBytes < 0 || rec.Evidence.MemoryRemainingBytes < 0 ||
		rec.Evidence.MemoryRemainingBytes > rec.Evidence.MemoryBudgetBytes {
		return fmt.Errorf("invalid memory evidence")
	}
	if rec.Evidence.EstimatedBytes <= 0 {
		return fmt.Errorf("invalid estimated bytes")
	}
	return nil
}

func verifyClocks(rec model.Record) error {
	if len(rec.Observations) != 2 {
		return fmt.Errorf("expected two clocks")
	}
	a, b := rec.Observations[0], rec.Observations[1]
	if a.DeviceID != "device-a" || a.ClockRole != "primary" ||
		b.DeviceID != "device-b" || b.ClockRole != "secondary" {
		return fmt.Errorf("unexpected clock identities")
	}
	if a.CorrectedTSNS != a.RawTSNS-a.ClockOffsetNS ||
		b.CorrectedTSNS != b.RawTSNS-b.ClockOffsetNS {
		return fmt.Errorf("clock correction arithmetic mismatch")
	}
	if a.CorrectedTSNS != b.CorrectedTSNS {
		return fmt.Errorf("clocks were not reconciled to one timeline")
	}
	if rec.CanonicalDevice != a.DeviceID || rec.CanonicalTSNS != a.CorrectedTSNS {
		return fmt.Errorf("canonical event does not identify an observation")
	}
	if rec.Evidence.ClockCorrectionNS != b.ClockOffsetNS {
		return fmt.Errorf("clock correction evidence mismatch")
	}
	if b.SkewMS != rec.Evidence.ClockCorrectionNS/1e6 {
		return fmt.Errorf("skew milliseconds disagree with offset")
	}
	return nil
}

func verifyAnalysis(rec model.Record) error {
	if rec.Analysis.Format != "libfuzzer-corpus/v1" {
		return fmt.Errorf("unexpected analysis format %q", rec.Analysis.Format)
	}
	if rec.Analysis.ContentSHA256 != rec.InputSHA256 {
		return fmt.Errorf("analysis content hash mismatch")
	}
	if !validSHA(rec.Analysis.ResultSHA256) {
		return fmt.Errorf("invalid analysis result hash")
	}
	switch rec.Mode {
	case model.ModeFull:
		if rec.DegradedReason != "" {
			return fmt.Errorf("full record has degraded reason %q", rec.DegradedReason)
		}
		if rec.Analysis.CoverageBytes != int(rec.InputBytes) ||
			rec.Analysis.Features > 256 {
			return fmt.Errorf("invalid full analysis counters")
		}
	case model.ModeDegraded:
		if rec.DegradedReason == "" || rec.Analysis.Features != 0 ||
			rec.Analysis.CoverageBytes != 0 {
			return fmt.Errorf("degraded record leaked content features")
		}
	default:
		return fmt.Errorf("unknown mode %q", rec.Mode)
	}
	if rec.Duplicate {
		if rec.Mode == model.ModeDegraded && rec.Decision != model.DecisionMetadataRepeat {
			return fmt.Errorf("duplicate degraded decision mismatch")
		}
		if rec.Mode == model.ModeFull && rec.Decision != model.DecisionAnalyzedRepeat {
			return fmt.Errorf("duplicate full decision mismatch")
		}
	} else {
		if rec.Mode == model.ModeDegraded && rec.Decision != model.DecisionMetadataOnly {
			return fmt.Errorf("degraded decision mismatch")
		}
		if rec.Mode == model.ModeFull && rec.Decision != model.DecisionAnalyzed {
			return fmt.Errorf("full decision mismatch")
		}
	}
	return nil
}

func verifyInput(dir string, rec model.Record, input InputFile) error {
	rel, err := safeRel(rec.InputName)
	if err != nil {
		return err
	}
	wantName := filepath.ToSlash(filepath.Join("inputs", rel))
	if input.Seq != rec.Seq || input.Name != wantName ||
		input.SHA256 != rec.InputSHA256 || input.Bytes != rec.InputBytes {
		return fmt.Errorf("input manifest entry mismatch")
	}
	sha, size, err := hashFile(filepath.Join(dir, filepath.FromSlash(input.Name)))
	if err != nil {
		return err
	}
	if sha != rec.InputSHA256 || size != rec.InputBytes {
		return fmt.Errorf("input bytes mismatch: sha=%s bytes=%d", sha, size)
	}
	return nil
}

func validSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func decodeCheckpoints(dir string, ex *Export) error {
	lines, err := readLines(filepath.Join(dir, checkpointsFile))
	if err != nil {
		return err
	}
	if len(lines) != ex.Manifest.CheckpointCount {
		return fmt.Errorf("checkpoint count mismatch")
	}
	for i, line := range lines {
		if err := CheckOrder(line, model.CheckpointFields); err != nil {
			return fmt.Errorf("checkpoint %d order: %w", i+1, err)
		}
		var c model.Checkpoint
		if err := json.Unmarshal(line, &c); err != nil {
			return err
		}
		if c.Schema != model.SchemaVersion || c.RecordType != "checkpoint" ||
			c.RunID != ex.Manifest.RunID || c.Seq != int64(i+1) {
			return fmt.Errorf("checkpoint %d identity/order mismatch", i+1)
		}
		if got := model.CheckpointDigest(c); got != c.StateDigest {
			return fmt.Errorf("checkpoint %d state digest mismatch", c.Seq)
		}
		if c.Cursor < 0 || c.CompletedCount != c.Cursor {
			return fmt.Errorf("checkpoint %d cursor invalid", c.Seq)
		}
		ex.Checkpoints = append(ex.Checkpoints, c)
	}
	if len(ex.Checkpoints) > 0 {
		last := ex.Checkpoints[len(ex.Checkpoints)-1]
		if last.ResultDigest != ex.Manifest.ResultDigest {
			return fmt.Errorf("final checkpoint digest does not match export")
		}
	}
	return nil
}

func decodeEvents(dir string, ex *Export) error {
	lines, err := readLines(filepath.Join(dir, eventsFile))
	if err != nil {
		return err
	}
	if len(lines) != ex.Manifest.EventCount {
		return fmt.Errorf("event count mismatch")
	}
	for i, line := range lines {
		if err := CheckOrder(line, model.EventFields); err != nil {
			return fmt.Errorf("event %d order: %w", i+1, err)
		}
		var e model.Event
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		if e.Schema != model.SchemaVersion || e.RecordType != "event" ||
			e.RunID != ex.Manifest.RunID || e.Seq != int64(i+1) {
			return fmt.Errorf("event %d identity/order mismatch", i+1)
		}
		ex.Events = append(ex.Events, e)
	}
	return nil
}

func decodeComparisons(dir string, ex *Export) error {
	lines, err := readLines(filepath.Join(dir, comparisonsFile))
	if err != nil {
		return err
	}
	if len(lines) != ex.Manifest.ComparisonCount {
		return fmt.Errorf("comparison count mismatch")
	}
	for i, line := range lines {
		if err := CheckOrder(line, model.ComparisonFields); err != nil {
			return fmt.Errorf("comparison %d order: %w", i+1, err)
		}
		var c model.Comparison
		if err := json.Unmarshal(line, &c); err != nil {
			return err
		}
		if c.Schema != model.SchemaVersion || c.RecordType != "comparison" ||
			c.RunID != ex.Manifest.RunID || c.Seq != int64(i+1) ||
			c.Cursor < 0 || c.ComparedRecords < 0 {
			return fmt.Errorf("comparison %d identity mismatch", i+1)
		}
		ex.Comparisons = append(ex.Comparisons, c)
	}
	return nil
}

func verifyFlow(m *Manifest, records []model.Record, checkpoints []model.Checkpoint, events []model.Event, comparisons []model.Comparison) error {
	allMatch := true
	final := false
	restore := false
	resumed := false
	for _, cp := range checkpoints {
		if cp.Cursor > int64(len(records)) {
			return fmt.Errorf("checkpoint %d cursor exceeds records", cp.Seq)
		}
		if got := model.ResultDigest(records[:cp.Cursor]); got != cp.ResultDigest {
			return fmt.Errorf("checkpoint %d result digest does not match record prefix", cp.Seq)
		}
	}
	for _, e := range events {
		if e.Kind == "resume" {
			resumed = true
		}
	}
	for _, c := range comparisons {
		if !c.Match {
			allMatch = false
		}
		if c.Phase == "final_recompute" && c.Match {
			final = true
		}
		if c.Phase == "resume_restore" && c.Match {
			restore = true
			found := false
			for _, cp := range checkpoints {
				if cp.Cursor == c.Cursor && cp.ResultDigest == c.BeforeDigest &&
					c.AfterDigest == c.BeforeDigest {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("resume comparison at cursor %d has no matching checkpoint", c.Cursor)
			}
		}
		if c.Phase == "final_recompute" {
			if c.Match && c.AfterDigest != m.ResultDigest {
				return fmt.Errorf("final comparison after_digest disagrees with export")
			}
			if c.Match && (c.BeforeDigest != m.ResultDigest || c.Cursor != int64(m.RecordCount)) {
				return fmt.Errorf("final comparison does not cover the exported result")
			}
		}
	}
	if allMatch != m.ComparisonsPass {
		return fmt.Errorf("manifest comparisons_pass=%t but records disagree", m.ComparisonsPass)
	}
	finalized := m.Status == "completed" || m.Status == "completed_degraded"
	if finalized != m.Finalized {
		return fmt.Errorf("manifest finalized flag disagrees with status")
	}
	if finalized && !final {
		return fmt.Errorf("finalized export lacks a matching final_recompute")
	}
	if resumed && !restore {
		return fmt.Errorf("resumed export lacks a matching resume_restore")
	}
	return nil
}

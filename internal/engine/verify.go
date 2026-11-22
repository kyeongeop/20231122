package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"mountaudit/internal/audit"
	"mountaudit/internal/store"
)

type VerifyResult struct {
	RunID       string `json:"run_id"`
	Equal       bool   `json:"equal"`
	Stages      int    `json:"stages_compared"`
	Comparisons int    `json:"comparisons_written"`
	FinalDigest string `json:"final_digest"`
}

func compareCompleted(
	ctx context.Context,
	st *store.Store,
	run store.Run,
	plan audit.Plan,
	checkpoints []store.Checkpoint,
	records []store.RecordRow,
	findings []store.FindingRow,
	clock func() time.Time,
) (map[int]string, int, error) {
	digests := make(map[int]string, 3)
	if len(checkpoints) == 0 {
		return digests, 0, nil
	}
	prior := make([]audit.MountRecord, 0, len(records))
	comparisons := 0
	for index, checkpoint := range checkpoints {
		expectedStage := index + 1
		if checkpoint.Stage != expectedStage {
			return digests, comparisons, fmt.Errorf("checkpoint gap: expected stage %d, found %d",
				expectedStage, checkpoint.Stage)
		}
		first, last := plan.StageRange(expectedStage, scanLimit(run.Limits, int64(len(run.Original))))
		current := computeStage(run.Original, plan, run.Limits, expectedStage, prior)
		currentDigest := current.Digest()
		currentSegment := audit.SHA256Hex(run.Original[first:last])
		tableEqual := stageRowsEqual(current, records, findings, checkpoint.FinishedAt)
		equal := currentDigest == checkpoint.ResultSHA &&
			currentSegment == checkpoint.SegmentSHA && tableEqual
		digests[expectedStage] = currentDigest

		detailBytes, _ := json.Marshal(map[string]any{
			"stage":               expectedStage,
			"start_offset":        first,
			"end_offset":          last,
			"segment_sha256":      currentSegment,
			"result_sha256":       currentDigest,
			"records":             len(current.Records),
			"findings":            len(current.Findings),
			"degraded":            current.Degraded,
			"degraded_reasons":    current.DegradedReason,
			"prior_result_sha256": checkpoint.ResultSHA,
			"table_rows_equal":    tableEqual,
		})
		comparedAt := audit.FormatTime(audit.NowUTC(clock))
		if err := st.AddComparison(ctx, run.ID, store.Comparison{
			ComparedAt:  comparedAt,
			Scope:       fmt.Sprintf("resume-replay:stage:%d", expectedStage),
			PriorSHA256: checkpoint.ResultSHA,
			CurrentSHA:  currentDigest,
			Equal:       equal,
			DetailJSON:  string(detailBytes),
		}); err != nil {
			return digests, comparisons, err
		}
		comparisons++
		if !equal {
			if err := markIntegrityError(ctx, st, run, expectedStage, first, last,
				checkpoint.ResultSHA, currentDigest, comparedAt); err != nil {
				return digests, comparisons, err
			}
			return digests, comparisons, fmt.Errorf(
				"stage %d replay differs from checkpoint at offsets [%d,%d)", expectedStage, first, last)
		}
		prior = append(prior, current.Records...)
	}

	if len(checkpoints) == 3 {
		expectedFinal := audit.FinalDigest(run.SourceSHA256, plan.Anchors, []string{
			digests[1], digests[2], digests[3],
		})
		equal := expectedFinal == run.FinalDigest
		detailBytes, _ := json.Marshal(map[string]any{
			"expected_final_digest": expectedFinal,
			"recorded_final_digest": run.FinalDigest,
			"offsets":               []int64{0, int64(len(run.Original))},
		})
		comparedAt := audit.FormatTime(audit.NowUTC(clock))
		if err := st.AddComparison(ctx, run.ID, store.Comparison{
			ComparedAt:  comparedAt,
			Scope:       "resume-replay:final",
			PriorSHA256: run.FinalDigest,
			CurrentSHA:  expectedFinal,
			Equal:       equal,
			DetailJSON:  string(detailBytes),
		}); err != nil {
			return digests, comparisons, err
		}
		comparisons++
		if !equal {
			if err := markIntegrityError(ctx, st, run, 3, 0, int64(len(run.Original)),
				run.FinalDigest, expectedFinal, comparedAt); err != nil {
				return digests, comparisons, err
			}
			return digests, comparisons, fmt.Errorf("final replay digest differs from recorded digest")
		}
	}
	return digests, comparisons, nil
}

func markIntegrityError(
	ctx context.Context,
	st *store.Store,
	run store.Run,
	stage int,
	start, end int64,
	priorSHA, currentSHA, capturedAt string,
) error {
	detail, _ := json.Marshal(map[string]any{
		"stage":          stage,
		"prior_sha256":   priorSHA,
		"current_sha256": currentSHA,
		"start_offset":   start,
		"end_offset":     end,
		"policy":         "fail closed; original and checkpoints retained",
	})
	if err := st.AddEvidence(ctx, run.ID, store.Evidence{
		Kind:        "integrity_mismatch",
		CapturedAt:  capturedAt,
		StartOffset: start,
		EndOffset:   end,
		SHA256:      currentSHA,
		DetailJSON:  string(detail),
	}); err != nil {
		return err
	}
	return st.SetRunError(ctx, run.ID, "integrity_error",
		fmt.Sprintf("stage %d replay mismatch", stage), capturedAt)
}

func Verify(ctx context.Context, st *store.Store, runID string, clock func() time.Time) (VerifyResult, error) {
	var result VerifyResult
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return result, err
	}
	result.RunID = run.ID
	artifactAvailable, err := validateOriginal(run)
	if err != nil {
		return result, err
	}
	if !artifactAvailable {
		now := audit.NowUTC(clock)
		detail, _ := json.Marshal(map[string]any{
			"artifact_path": run.ArtifactPath,
			"fallback":      "sqlite original blob",
		})
		if err := st.AddEvidence(ctx, runID, store.Evidence{
			Kind:        "artifact_missing_fallback",
			CapturedAt:  audit.FormatTime(now),
			StartOffset: 0,
			EndOffset:   int64(len(run.Original)),
			SHA256:      run.SourceSHA256,
			DetailJSON:  string(detail),
		}); err != nil {
			return result, err
		}
	}
	anchors, err := st.GetAnchors(ctx, runID)
	if err != nil {
		return result, err
	}
	checkpoints, err := st.GetCheckpoints(ctx, runID)
	if err != nil {
		return result, err
	}
	records, err := st.GetRecords(ctx, runID)
	if err != nil {
		return result, err
	}
	findings, err := st.GetFindings(ctx, runID)
	if err != nil {
		return result, err
	}
	if len(checkpoints) == 0 {
		return result, fmt.Errorf("run has no completed checkpoints")
	}
	plan := planFromAnchors(run.Original, anchors)
	digests, comparisons, err := compareCompleted(ctx, st, run, plan, checkpoints, records, findings, clock)
	if err != nil {
		return result, err
	}
	result.Stages = len(checkpoints)
	result.Comparisons = comparisons
	if len(checkpoints) == 3 {
		result.FinalDigest = audit.FinalDigest(run.SourceSHA256, anchors, []string{
			digests[1], digests[2], digests[3],
		})
	}
	result.Equal = true
	evidenceAt := audit.FormatTime(audit.NowUTC(clock))
	detail, _ := json.Marshal(map[string]any{
		"stages":          result.Stages,
		"comparisons":     result.Comparisons,
		"final_digest":    result.FinalDigest,
		"original_sha256": run.SourceSHA256,
		"source_path":     run.SourcePath,
		"artifact_path":   run.ArtifactPath,
	})
	if err := st.AddEvidence(ctx, runID, store.Evidence{
		Kind:        "verification",
		CapturedAt:  evidenceAt,
		StartOffset: 0,
		EndOffset:   int64(len(run.Original)),
		SHA256:      result.FinalDigest,
		DetailJSON:  string(detail),
	}); err != nil {
		return result, err
	}
	return result, nil
}

func stageRowsEqual(
	result audit.StageResult,
	records []store.RecordRow,
	findings []store.FindingRow,
	finishedAt string,
) bool {
	expectedRecords, _ := json.Marshal(result.Records)
	var dbRecords []audit.MountRecord
	for _, row := range records {
		if row.Stage == result.Stage {
			if row.ObservedAt != finishedAt {
				return false
			}
			dbRecords = append(dbRecords, row.MountRecord)
		}
	}
	actualRecords, _ := json.Marshal(dbRecords)

	var dbFindings []audit.Finding
	for _, row := range findings {
		if row.Stage == result.Stage {
			if row.ObservedAt != finishedAt {
				return false
			}
			finding := row.Finding
			finding.Ordinal = 0
			dbFindings = append(dbFindings, finding)
		}
	}
	audit.SortFindings(dbFindings)
	expectedFindings, _ := json.Marshal(result.Findings)
	actualFindings, _ := json.Marshal(dbFindings)
	return string(expectedRecords) == string(actualRecords) &&
		string(expectedFindings) == string(actualFindings)
}

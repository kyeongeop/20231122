package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"mountaudit/internal/audit"
	"mountaudit/internal/store"
)

type Options struct {
	PauseAfter int
}

type Result struct {
	RunID       string `json:"run_id"`
	Status      string `json:"status"`
	NextStage   int    `json:"next_stage"`
	Degraded    bool   `json:"degraded"`
	FinalDigest string `json:"final_digest,omitempty"`
	Comparisons int    `json:"comparisons"`
}

func Process(ctx context.Context, st *store.Store, runID string, options Options, clock func() time.Time) (Result, error) {
	var result Result
	if options.PauseAfter < 0 || options.PauseAfter > 3 {
		return result, fmt.Errorf("pause-after must be between 1 and 3")
	}
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return result, err
	}
	result.RunID = run.ID
	artifactAvailable, err := validateOriginal(run)
	if err != nil {
		return result, err
	}
	if run.Status == "completed" || run.Status == "degraded" {
		result.Status = run.Status
		result.NextStage = run.NextStage
		result.Degraded = run.Degraded
		result.FinalDigest = run.FinalDigest
		return result, nil
	}
	if run.Status == "integrity_error" || run.Status == "failed" {
		return result, fmt.Errorf("run %s is %s: %s", run.ID, run.Status, run.Error)
	}
	anchors, err := st.GetAnchors(ctx, runID)
	if err != nil {
		return result, err
	}
	plan := planFromAnchors(run.Original, anchors)
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
	evidence, err := st.GetEvidence(ctx, runID)
	if err != nil {
		return result, err
	}
	stageDigests, comparisons, err := compareCompleted(
		ctx, st, run, plan, checkpoints, records, findings, clock)
	if err != nil {
		return result, err
	}
	result.Comparisons = comparisons
	if len(checkpoints) == 3 {
		result.Status = run.Status
		result.NextStage = run.NextStage
		result.Degraded = run.Degraded
		result.FinalDigest = run.FinalDigest
		return result, nil
	}
	if run.NextStage != len(checkpoints)+1 {
		return result, fmt.Errorf("run next_stage=%d but %d checkpoints are committed",
			run.NextStage, len(checkpoints))
	}

	priorRecords := make([]audit.MountRecord, 0, len(records))
	for _, row := range records {
		priorRecords = append(priorRecords, row.MountRecord)
	}
	nextFinding := len(findings) + 1
	hasScanEvidence := containsKind(evidence, "resource_scan_budget")
	runDegraded := run.Degraded
	if !artifactAvailable {
		runDegraded = true
		now := audit.NowUTC(clock)
		detail, _ := json.Marshal(map[string]any{
			"artifact_path": run.ArtifactPath,
			"fallback":      "use immutable sqlite original blob",
		})
		if err := st.AddEvidence(ctx, run.ID, store.Evidence{
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
	totalBytes := int64(len(run.Original))
	effectiveScan := scanLimit(run.Limits, totalBytes)

	for stage := run.NextStage; stage <= 3; stage++ {
		started := audit.NowUTC(clock)
		stageResult := computeStage(run.Original, plan, run.Limits, stage, priorRecords)
		finished := audit.NowUTC(clock)
		stageDigest := stageResult.Digest()
		stageDigests[stage] = stageDigest

		if stageResult.Degraded || effectiveScan < totalBytes {
			runDegraded = true
		}
		start, end := stageResult.StartOffset, stageResult.EndOffset
		segmentSHA := audit.SHA256Hex(run.Original[start:end])
		if stageResult.Degraded {
			stageResult.Degraded = true
		}
		stageJSON, err := json.Marshal(stageResult)
		if err != nil {
			return result, fmt.Errorf("encode stage %d result: %w", stage, err)
		}

		stageEvidence := []store.Evidence{stageAnchorEvidence(stageResult, segmentSHA, stageDigest, finished)}
		if stage == 1 && effectiveScan < totalBytes && !hasScanEvidence {
			stageEvidence = append(stageEvidence, scanBudgetEvidence(run, totalBytes, effectiveScan, finished))
			hasScanEvidence = true
		}
		for _, issue := range stageResult.ParseIssues {
			detail, _ := json.Marshal(issue)
			stageEvidence = append(stageEvidence, store.Evidence{
				Kind:        "parse_issue",
				CapturedAt:  audit.FormatTime(finished),
				StartOffset: issue.StartOffset,
				EndOffset:   issue.EndOffset,
				SHA256:      audit.SHA256Hex(run.Original[issue.StartOffset:issue.EndOffset]),
				DetailJSON:  string(detail),
			})
		}
		if hasReason(stageResult, "record_budget_exceeded") ||
			hasReason(stageResult, "record_budget_already_exhausted") {
			detail, _ := json.Marshal(map[string]any{
				"max_records":    run.Limits.MaxRecords,
				"records_before": len(priorRecords),
				"records_added":  len(stageResult.Records),
				"stop_offset":    stageResult.StopOffset,
			})
			stageEvidence = append(stageEvidence, store.Evidence{
				Kind:        "resource_record_quota",
				CapturedAt:  audit.FormatTime(finished),
				StartOffset: stageResult.StartOffset,
				EndOffset:   stageResult.StopOffset,
				SHA256:      audit.SHA256Hex(run.Original[stageResult.StartOffset:stageResult.StopOffset]),
				DetailJSON:  string(detail),
			})
		}

		recordRows := make([]store.RecordRow, 0, len(stageResult.Records))
		for _, record := range stageResult.Records {
			recordRows = append(recordRows, store.RecordRow{
				MountRecord: record,
				ObservedAt:  audit.FormatTime(finished),
			})
		}
		findingRows := make([]store.FindingRow, 0, len(stageResult.Findings))
		for _, finding := range stageResult.Findings {
			finding.Ordinal = nextFinding
			nextFinding++
			findingRows = append(findingRows, store.FindingRow{
				Finding:    finding,
				ObservedAt: audit.FormatTime(finished),
			})
		}

		status := "running"
		nextStage := stage + 1
		if options.PauseAfter == stage {
			status = "paused"
		} else if stage == 3 {
			nextStage = 4
			if runDegraded {
				status = "degraded"
			} else {
				status = "completed"
			}
		}
		finalDigest := ""
		if stage == 3 && completeDigests(stageDigests) {
			finalDigest = audit.FinalDigest(run.SourceSHA256, anchors, []string{
				stageDigests[1], stageDigests[2], stageDigests[3],
			})
		}
		checkpoint := store.Checkpoint{
			RunID:        run.ID,
			Stage:        stage,
			AnchorNumber: stage,
			Status:       "done",
			StartedAt:    audit.FormatTime(started),
			FinishedAt:   audit.FormatTime(finished),
			StartOffset:  stageResult.StartOffset,
			EndOffset:    stageResult.EndOffset,
			AnchorOffset: stageResult.AnchorOffset,
			AnchorLine:   stageResult.AnchorLine,
			SegmentSHA:   segmentSHA,
			ResultJSON:   string(stageJSON),
			ResultSHA:    stageDigest,
			Degraded:     stageResult.Degraded,
		}
		commit := store.StageCommit{
			Checkpoint:  checkpoint,
			Records:     recordRows,
			Findings:    findingRows,
			Evidence:    stageEvidence,
			RunStatus:   status,
			NextStage:   nextStage,
			Degraded:    runDegraded,
			FinalDigest: finalDigest,
			UpdatedAt:   audit.FormatTime(finished),
		}
		if err := st.CommitStage(ctx, run.ID, commit); err != nil {
			return result, err
		}
		priorRecords = append(priorRecords, stageResult.Records...)
		result.Status = status
		result.NextStage = nextStage
		result.Degraded = runDegraded
		result.FinalDigest = finalDigest
		if status == "paused" {
			return result, nil
		}
	}
	return result, nil
}

func validateOriginal(run store.Run) (bool, error) {
	if int64(len(run.Original)) != run.SourceSize {
		return false, fmt.Errorf("stored original size %d differs from recorded size %d",
			len(run.Original), run.SourceSize)
	}
	if actual := audit.SHA256Hex(run.Original); actual != run.SourceSHA256 {
		return false, fmt.Errorf("stored original sha256 %s differs from recorded %s", actual, run.SourceSHA256)
	}
	if info, err := os.Stat(run.ArtifactPath); err == nil {
		if info.Mode().Perm()&0o222 != 0 {
			return true, fmt.Errorf("original artifact %s is writable", run.ArtifactPath)
		}
		bytes, err := os.ReadFile(run.ArtifactPath)
		if err != nil {
			return true, fmt.Errorf("read original artifact: %w", err)
		}
		if audit.SHA256Hex(bytes) != run.SourceSHA256 {
			return true, fmt.Errorf("original artifact checksum differs from database")
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat original artifact: %w", err)
	}
	return false, nil
}

func planFromAnchors(data []byte, anchors []audit.Anchor) audit.Plan {
	boundaries := [4]int64{0, anchors[0].Offset, anchors[1].Offset, int64(len(data))}
	for index := 1; index < len(boundaries); index++ {
		if boundaries[index] < boundaries[index-1] {
			boundaries[index] = boundaries[index-1]
		}
	}
	return audit.Plan{
		Anchors:        anchors,
		AnchorFallback: !anchors[0].Explicit,
		Boundaries:     boundaries,
	}
}

func stageAnchorEvidence(result audit.StageResult, segmentSHA, resultSHA string, captured time.Time) store.Evidence {
	detail, _ := json.Marshal(map[string]any{
		"stage":            result.Stage,
		"anchor_number":    result.AnchorNumber,
		"anchor_offset":    result.AnchorOffset,
		"anchor_line":      result.AnchorLine,
		"start_offset":     result.StartOffset,
		"end_offset":       result.EndOffset,
		"segment_sha256":   segmentSHA,
		"result_sha256":    resultSHA,
		"scanned_bytes":    result.ScannedBytes,
		"records":          len(result.Records),
		"findings":         len(result.Findings),
		"degraded":         result.Degraded,
		"degraded_reasons": result.DegradedReason,
	})
	return store.Evidence{
		Kind:        "stage_anchor",
		CapturedAt:  audit.FormatTime(captured),
		StartOffset: result.StartOffset,
		EndOffset:   result.EndOffset,
		SHA256:      segmentSHA,
		DetailJSON:  string(detail),
	}
}

func scanBudgetEvidence(run store.Run, total, effective int64, captured time.Time) store.Evidence {
	detail, _ := json.Marshal(map[string]any{
		"requested_bytes": total,
		"effective_bytes": effective,
		"max_scan_bytes":  run.Limits.MaxScanBytes,
		"fallback":        "analyze prefix, retain full original, mark report incomplete",
	})
	return store.Evidence{
		Kind:        "resource_scan_budget",
		CapturedAt:  audit.FormatTime(captured),
		StartOffset: 0,
		EndOffset:   effective,
		SHA256:      audit.SHA256Hex(run.Original[:effective]),
		DetailJSON:  string(detail),
	}
}

func hasReason(result audit.StageResult, reason string) bool {
	for _, item := range result.DegradedReason {
		if item == reason {
			return true
		}
	}
	return false
}

func completeDigests(digests map[int]string) bool {
	return digests[1] != "" && digests[2] != "" && digests[3] != ""
}

func containsKind(evidence []store.Evidence, kind string) bool {
	for _, item := range evidence {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

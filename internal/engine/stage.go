package engine

import (
	"mountaudit/internal/audit"
)

func scanLimit(limits audit.Limits, total int64) int64 {
	limit := total
	if limits.MaxScanBytes > 0 && limit > limits.MaxScanBytes {
		limit = limits.MaxScanBytes
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func computeStage(data []byte, plan audit.Plan, limits audit.Limits, stage int, prior []audit.MountRecord) audit.StageResult {
	start, end := plan.StageRange(stage, scanLimit(limits, int64(len(data))))
	anchor := plan.Anchors[stage-1]
	result := audit.StageResult{
		Schema:       "mountaudit.stage/v1",
		Stage:        stage,
		AnchorNumber: stage,
		AnchorOffset: anchor.Offset,
		AnchorLine:   anchor.Line,
		StartOffset:  start,
		EndOffset:    end,
		ScannedBytes: end - start,
	}
	if start < end {
		if limit := plan.Boundaries[stage]; limit > end {
			result.Degraded = true
			result.DegradedReason = append(result.DegradedReason, "scan_byte_budget_exceeded")
		}
	}

	remaining := limits.MaxRecords - len(prior)
	if remaining < 0 {
		remaining = 0
	}
	if start < end && remaining == 0 {
		result.Degraded = true
		result.DegradedReason = append(result.DegradedReason, "record_budget_already_exhausted")
		result.StopOffset = start
	} else if start < end {
		parsed := audit.ParseRange(data, start, end, stage, len(prior), remaining)
		result.Records = parsed.Records
		result.Findings = parsed.Findings
		result.ParseIssues = parsed.Issues
		result.StopOffset = parsed.StopOffset
		if parsed.Truncated {
			result.Degraded = true
			result.DegradedReason = append(result.DegradedReason, "record_budget_exceeded")
		}
	}

	if stage == 3 {
		allRecords := make([]audit.MountRecord, 0, len(prior)+len(result.Records))
		allRecords = append(allRecords, prior...)
		allRecords = append(allRecords, result.Records...)
		result.Findings = append(result.Findings, audit.AggregateFindings(allRecords)...)
	}
	audit.SortFindings(result.Findings)
	return result
}

func recordsFrom(result audit.StageResult) []audit.MountRecord {
	return append([]audit.MountRecord(nil), result.Records...)
}

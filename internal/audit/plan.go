package audit

import "time"

type Plan struct {
	Anchors        []Anchor
	AnchorFallback bool
	FallbackReason string
	Boundaries     [4]int64
}

func MakePlan(data []byte, clock func() time.Time) Plan {
	resolved := ResolveAnchors(data, clock)
	anchors := resolved.Anchors
	boundaries := [4]int64{0, anchors[0].Offset, anchors[1].Offset, int64(len(data))}
	if anchors[2].Offset < boundaries[3] {
		boundaries[3] = int64(len(data))
	}
	for index := 1; index < len(boundaries); index++ {
		if boundaries[index] < boundaries[index-1] {
			boundaries[index] = boundaries[index-1]
		}
	}
	return Plan{
		Anchors:        anchors,
		AnchorFallback: resolved.Fallback,
		FallbackReason: resolved.Reason,
		Boundaries:     boundaries,
	}
}

func (p Plan) StageRange(stage int, scanLimit int64) (int64, int64) {
	if stage < 1 || stage > 3 {
		return 0, 0
	}
	if scanLimit < 0 {
		scanLimit = 0
	}
	end := p.Boundaries[stage]
	if end > scanLimit {
		end = scanLimit
	}
	start := p.Boundaries[stage-1]
	if start > end {
		start = end
	}
	return start, end
}

type Analysis struct {
	Plan           Plan
	Stages         []StageResult
	Records        []MountRecord
	Findings       []Finding
	Issues         []ParseIssue
	Degraded       bool
	DegradedReason []string
	ScannedBytes   int64
	TotalBytes     int64
	StopOffset     int64
}

func Analyze(data []byte, limits Limits, clock func() time.Time) Analysis {
	plan := MakePlan(data, clock)
	analysis := Analysis{
		Plan:       plan,
		TotalBytes: int64(len(data)),
	}
	if plan.AnchorFallback {
		analysis.Degraded = true
		analysis.DegradedReason = append(analysis.DegradedReason, "anchor_fallback: "+plan.FallbackReason)
	}
	scanLimit := int64(len(data))
	if limits.MaxScanBytes > 0 && scanLimit > limits.MaxScanBytes {
		scanLimit = limits.MaxScanBytes
		analysis.Degraded = true
		analysis.DegradedReason = append(analysis.DegradedReason,
			"scan_byte_budget_exceeded: analyzed prefix only")
	}

	remaining := limits.MaxRecords
	if remaining <= 0 {
		remaining = limits.MaxRecords
	}
	for stage := 1; stage <= 3; stage++ {
		start, end := plan.StageRange(stage, scanLimit)
		result := StageResult{
			Schema:       "mountaudit.stage/v1",
			Stage:        stage,
			AnchorNumber: stage,
			AnchorOffset: plan.Anchors[stage-1].Offset,
			AnchorLine:   plan.Anchors[stage-1].Line,
			StartOffset:  start,
			EndOffset:    end,
			ScannedBytes: end - start,
		}
		if remaining > 0 {
			parsed := ParseRange(data, start, end, stage, len(analysis.Records), remaining)
			result.Records = parsed.Records
			result.Findings = parsed.Findings
			result.ParseIssues = parsed.Issues
			result.StopOffset = parsed.StopOffset
			remaining -= len(parsed.Records)
			if parsed.Truncated {
				result.Degraded = true
				result.DegradedReason = append(result.DegradedReason, "record_budget_exceeded")
				analysis.Degraded = true
				analysis.DegradedReason = append(analysis.DegradedReason, "record_budget_exceeded")
				if analysis.StopOffset == 0 || parsed.StopOffset < analysis.StopOffset {
					analysis.StopOffset = parsed.StopOffset
				}
			}
		} else if start < end {
			result.Degraded = true
			result.DegradedReason = append(result.DegradedReason, "record_budget_already_exhausted")
		}
		if stage == 3 {
			allRecords := append([]MountRecord(nil), analysis.Records...)
			allRecords = append(allRecords, result.Records...)
			result.Findings = append(result.Findings, AggregateFindings(allRecords)...)
			SortFindings(result.Findings)
		}
		analysis.Stages = append(analysis.Stages, result)
		analysis.Records = append(analysis.Records, result.Records...)
		analysis.Findings = append(analysis.Findings, result.Findings...)
		analysis.Issues = append(analysis.Issues, result.ParseIssues...)
		analysis.ScannedBytes += result.ScannedBytes
	}
	if scanLimit < int64(len(data)) || analysis.StopOffset > 0 {
		if analysis.StopOffset == 0 {
			analysis.StopOffset = scanLimit
		}
	}
	return analysis
}

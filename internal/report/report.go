package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mountaudit/internal/audit"
	"mountaudit/internal/store"
)

type Report struct {
	Schema      string           `json:"schema"`
	GeneratedAt string           `json:"generated_at"`
	Run         RunSummary       `json:"run"`
	Original    OriginalSummary  `json:"original"`
	Anchors     []audit.Anchor   `json:"anchors"`
	Checkpoints []CheckpointView `json:"checkpoints"`
	Records     []RecordView     `json:"records"`
	Findings    []FindingView    `json:"findings"`
	Evidence    []EvidenceView   `json:"evidence"`
	Comparisons []ComparisonView `json:"comparisons"`
	Summary     Summary          `json:"summary"`
}

type RunSummary struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	NextStage   int    `json:"next_stage"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Format      string `json:"format"`
	Degraded    bool   `json:"degraded"`
	FinalDigest string `json:"final_digest,omitempty"`
	Error       string `json:"error,omitempty"`
}

type OriginalSummary struct {
	SourcePath   string `json:"source_path"`
	SourceName   string `json:"source_name"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	ArtifactPath string `json:"artifact_path"`
	ArtifactMode string `json:"artifact_mode"`
	Unmodified   bool   `json:"unmodified"`
}

type CheckpointView struct {
	Stage        int    `json:"stage"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	StartOffset  int64  `json:"start_offset"`
	EndOffset    int64  `json:"end_offset"`
	AnchorOffset int64  `json:"anchor_offset"`
	AnchorLine   int    `json:"anchor_line"`
	SegmentSHA   string `json:"segment_sha256"`
	ResultSHA    string `json:"result_sha256"`
	Degraded     bool   `json:"degraded"`
}

type RecordView struct {
	Ordinal     int               `json:"ordinal"`
	Stage       int               `json:"stage"`
	MountID     string            `json:"mount_id"`
	MountPoint  string            `json:"mount_point"`
	FSType      string            `json:"fs_type"`
	Source      string            `json:"source"`
	Permissions audit.Permissions `json:"permissions"`
	StartOffset int64             `json:"start_offset"`
	EndOffset   int64             `json:"end_offset"`
	Line        int               `json:"line"`
	ObservedAt  string            `json:"observed_at"`
	RawExcerpt  string            `json:"raw_excerpt"`
	RawSHA256   string            `json:"raw_sha256"`
}

type FindingView struct {
	Ordinal     int    `json:"ordinal"`
	Stage       int    `json:"stage"`
	Severity    string `json:"severity"`
	Code        string `json:"code"`
	MountPoint  string `json:"mount_point,omitempty"`
	Source      string `json:"source,omitempty"`
	Detail      string `json:"detail"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	Line        int    `json:"line"`
	ObservedAt  string `json:"observed_at"`
	RawExcerpt  string `json:"raw_excerpt"`
	RawSHA256   string `json:"raw_sha256"`
}

type EvidenceView struct {
	Ordinal     int    `json:"ordinal"`
	Kind        string `json:"kind"`
	CapturedAt  string `json:"captured_at"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
	SHA256      string `json:"sha256"`
	Detail      any    `json:"detail"`
}

type ComparisonView struct {
	Ordinal     int    `json:"ordinal"`
	ComparedAt  string `json:"compared_at"`
	Scope       string `json:"scope"`
	PriorSHA256 string `json:"prior_sha256"`
	CurrentSHA  string `json:"current_sha256"`
	Equal       bool   `json:"equal"`
	Detail      any    `json:"detail"`
}

type Summary struct {
	Records          int            `json:"records"`
	Findings         int            `json:"findings"`
	BySeverity       map[string]int `json:"by_severity"`
	Checkpoints      int            `json:"checkpoints"`
	PipelineComplete bool           `json:"pipeline_complete"`
	AnalysisComplete bool           `json:"analysis_complete"`
	Degraded         bool           `json:"degraded"`
	FinalDigest      string         `json:"final_digest,omitempty"`
}

func Build(ctx context.Context, st *store.Store, runID string, clock func() time.Time) (Report, error) {
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	anchors, err := st.GetAnchors(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	checkpoints, err := st.GetCheckpoints(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	records, err := st.GetRecords(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	findings, err := st.GetFindings(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	evidence, err := st.GetEvidence(ctx, runID)
	if err != nil {
		return Report{}, err
	}
	comparisons, err := st.GetComparisons(ctx, runID)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Schema:      "mountaudit.report/v1",
		GeneratedAt: audit.FormatTime(audit.NowUTC(clock)),
		Run: RunSummary{
			ID:          run.ID,
			Status:      run.Status,
			NextStage:   run.NextStage,
			CreatedAt:   run.CreatedAt,
			UpdatedAt:   run.UpdatedAt,
			Format:      run.Format,
			Degraded:    run.Degraded,
			FinalDigest: run.FinalDigest,
			Error:       run.Error,
		},
		Original: OriginalSummary{
			SourcePath:   run.SourcePath,
			SourceName:   run.SourceName,
			Size:         run.SourceSize,
			SHA256:       run.SourceSHA256,
			ArtifactPath: run.ArtifactPath,
			ArtifactMode: artifactMode(run.ArtifactPath),
			Unmodified:   true,
		},
		Anchors:     anchors,
		Checkpoints: make([]CheckpointView, 0, len(checkpoints)),
		Records:     make([]RecordView, 0, len(records)),
		Findings:    make([]FindingView, 0, len(findings)),
		Evidence:    make([]EvidenceView, 0, len(evidence)),
		Comparisons: make([]ComparisonView, 0, len(comparisons)),
		Summary: Summary{
			Records:          len(records),
			Findings:         len(findings),
			BySeverity:       make(map[string]int),
			Checkpoints:      len(checkpoints),
			PipelineComplete: len(checkpoints) == 3,
			AnalysisComplete: len(checkpoints) == 3 && !run.Degraded,
			Degraded:         run.Degraded,
			FinalDigest:      run.FinalDigest,
		},
	}
	for _, checkpoint := range checkpoints {
		report.Checkpoints = append(report.Checkpoints, CheckpointView{
			Stage:        checkpoint.Stage,
			Status:       checkpoint.Status,
			StartedAt:    checkpoint.StartedAt,
			FinishedAt:   checkpoint.FinishedAt,
			StartOffset:  checkpoint.StartOffset,
			EndOffset:    checkpoint.EndOffset,
			AnchorOffset: checkpoint.AnchorOffset,
			AnchorLine:   checkpoint.AnchorLine,
			SegmentSHA:   checkpoint.SegmentSHA,
			ResultSHA:    checkpoint.ResultSHA,
			Degraded:     checkpoint.Degraded,
		})
	}
	for _, record := range records {
		excerpt, rawSHA := excerpt(run.Original, record.StartOffset, record.EndOffset)
		report.Records = append(report.Records, RecordView{
			Ordinal:     record.Ordinal,
			Stage:       record.Stage,
			MountID:     record.MountID,
			MountPoint:  record.MountPoint,
			FSType:      record.FSType,
			Source:      record.Source,
			Permissions: record.Permissions,
			StartOffset: record.StartOffset,
			EndOffset:   record.EndOffset,
			Line:        record.Line,
			ObservedAt:  record.ObservedAt,
			RawExcerpt:  excerpt,
			RawSHA256:   rawSHA,
		})
	}
	for _, finding := range findings {
		excerpt, rawSHA := excerpt(run.Original, finding.StartOffset, finding.EndOffset)
		report.Findings = append(report.Findings, FindingView{
			Ordinal:     finding.Ordinal,
			Stage:       finding.Stage,
			Severity:    finding.Severity,
			Code:        finding.Code,
			MountPoint:  finding.MountPoint,
			Source:      finding.Source,
			Detail:      finding.Detail,
			StartOffset: finding.StartOffset,
			EndOffset:   finding.EndOffset,
			Line:        finding.Line,
			ObservedAt:  finding.ObservedAt,
			RawExcerpt:  excerpt,
			RawSHA256:   rawSHA,
		})
		report.Summary.BySeverity[finding.Severity]++
	}
	for _, item := range evidence {
		report.Evidence = append(report.Evidence, EvidenceView{
			Ordinal:     item.Ordinal,
			Kind:        item.Kind,
			CapturedAt:  item.CapturedAt,
			StartOffset: item.StartOffset,
			EndOffset:   item.EndOffset,
			SHA256:      item.SHA256,
			Detail:      decodeDetail(item.DetailJSON),
		})
	}
	for _, item := range comparisons {
		report.Comparisons = append(report.Comparisons, ComparisonView{
			Ordinal:     item.Ordinal,
			ComparedAt:  item.ComparedAt,
			Scope:       item.Scope,
			PriorSHA256: item.PriorSHA256,
			CurrentSHA:  item.CurrentSHA,
			Equal:       item.Equal,
			Detail:      decodeDetail(item.DetailJSON),
		})
	}
	return report, nil
}

func ArtifactMode(path string) string {
	return artifactMode(path)
}

func artifactMode(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

func excerpt(data []byte, start, end int64) (string, string) {
	if start < 0 {
		start = 0
	}
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	if start > end {
		start = end
	}
	raw := data[start:end]
	text := strconv.QuoteToASCII(string(raw))
	if len(text) > 4096 {
		text = text[:4093] + "..."
	}
	return text, audit.SHA256Hex(raw)
}

func decodeDetail(detail string) any {
	var value any
	if err := json.Unmarshal([]byte(detail), &value); err != nil {
		return detail
	}
	return value
}

func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r Report) Text() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "run=%s status=%s degraded=%t pipeline_complete=%t\n",
		r.Run.ID, r.Run.Status, r.Run.Degraded, r.Summary.PipelineComplete)
	fmt.Fprintf(&builder, "original=%s size=%d sha256=%s mode=%s unmodified=%t\n",
		r.Original.ArtifactPath, r.Original.Size, r.Original.SHA256,
		r.Original.ArtifactMode, r.Original.Unmodified)
	for _, anchor := range r.Anchors {
		fmt.Fprintf(&builder, "anchor=%d offset=%d line=%d captured_at=%s explicit=%t label=%s\n",
			anchor.Number, anchor.Offset, anchor.Line, anchor.CapturedAt,
			anchor.Explicit, anchor.Label)
	}
	for _, checkpoint := range r.Checkpoints {
		fmt.Fprintf(&builder,
			"checkpoint=%d status=%s start=%d end=%d started_at=%s finished_at=%s result_sha256=%s degraded=%t\n",
			checkpoint.Stage, checkpoint.Status, checkpoint.StartOffset,
			checkpoint.EndOffset, checkpoint.StartedAt, checkpoint.FinishedAt,
			checkpoint.ResultSHA, checkpoint.Degraded)
	}
	for _, finding := range r.Findings {
		fmt.Fprintf(&builder,
			"finding=%d severity=%s code=%s raw=[%d,%d) line=%d observed_at=%s\n",
			finding.Ordinal, finding.Severity, finding.Code, finding.StartOffset,
			finding.EndOffset, finding.Line, finding.ObservedAt)
	}
	for _, comparison := range r.Comparisons {
		fmt.Fprintf(&builder, "comparison=%d scope=%s equal=%t compared_at=%s\n",
			comparison.Ordinal, comparison.Scope, comparison.Equal, comparison.ComparedAt)
	}
	fmt.Fprintf(&builder, "final_digest=%s\n", r.Summary.FinalDigest)
	return builder.String()
}

package report

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/model"
)

type Options struct {
	EvidencePath string
	PolicyPath   string
	PolicySHA256 string
	GeneratedAt  time.Time
}

type runView struct {
	record        model.RunRecord
	logs          []evidence.LogEntry
	artifacts     []evidence.EvidenceRecord
	chainOK       bool
	artifactsOK   bool
	associationOK bool
	autoChecks    []check
	keyLogs       []evidence.LogEntry
}

type check struct {
	Name   string
	Status string
	Detail string
}

func Render(ctx context.Context, store *evidence.Store, opts Options) ([]byte, error) {
	runs, err := store.ListRuns(ctx)
	if err != nil {
		return nil, err
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	views := make([]runView, 0, len(runs))
	for _, record := range runs {
		view, err := loadRun(ctx, store, record)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].record.CreatedAt.Before(views[j].record.CreatedAt)
	})
	checks := automaticChecks(views, opts)
	var out bytes.Buffer
	writeHeader(&out, opts, checks)
	writeAutomatic(&out, views, checks)
	writeManual(&out, views, opts)
	writeFollowUps(&out, views, checks, opts)
	writeEvidenceAccess(&out, opts)
	return out.Bytes(), nil
}

func loadRun(ctx context.Context, store *evidence.Store, record model.RunRecord) (runView, error) {
	view := runView{record: record}
	var err error
	view.logs, err = store.Logs(ctx, record.RunID)
	if err != nil {
		return view, err
	}
	view.artifacts, err = store.Artifacts(ctx, record.RunID)
	if err != nil {
		return view, err
	}
	view.chainOK = store.VerifyChain(ctx, record.RunID) == nil
	view.artifactsOK = store.VerifyArtifacts(ctx, record.RunID) == nil
	view.associationOK = store.VerifyRun(ctx, record.RunID) == nil
	for _, entry := range view.logs {
		switch entry.Event {
		case "preflight", "permission_statement", "permission_decision", "statement_executed",
			"cancel_requested", "rollback", "commit", "pre_execution_failure", "post_commit_failure":
			view.keyLogs = append(view.keyLogs, entry)
		}
	}
	view.autoChecks = runChecks(view)
	return view, nil
}

func writeHeader(out *bytes.Buffer, opts Options, checks []check) {
	fmt.Fprintln(out, "# 数据库迁移权限复核报告")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "- 生成时间（UTC）：`%s`\n", opts.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "- 证据数据库：`%s`\n", opts.EvidencePath)
	fmt.Fprintf(out, "- 策略文件：`%s`\n", opts.PolicyPath)
	fmt.Fprintf(out, "- 自动复核结果：**%s**\n", overallStatus(checks))
	fmt.Fprintln(out, "- 人工复核状态：**未确认**（工具不会代替审批人签字）")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "> 本报告将确定性自动检查与人工判断严格分开。自动结论仅覆盖已记录的输入、权限判定、执行结果和证据哈希，不证明业务策略本身正确。")
	fmt.Fprintln(out)
}

func overallStatus(checks []check) string {
	for _, item := range checks {
		if item.Status == "FAIL" {
			return "FAIL"
		}
	}
	for _, item := range checks {
		if item.Status == "NOT_COVERED" {
			return "PARTIAL"
		}
	}
	return "PASS"
}

func runChecks(view runView) []check {
	hasInput := false
	hasDecision := false
	hasNormalized := false
	for _, artifact := range view.artifacts {
		switch artifact.Kind {
		case "input":
			hasInput = true
		case "permission":
			hasDecision = true
		case "manifest":
			hasNormalized = true
		}
	}
	return []check{
		{"输入证据", yesNo(hasInput), "raw input artifact"},
		{"权限证据", yesNo(hasDecision), "permission decision artifact"},
		{"归一化证据", yesNo(hasNormalized), "normalized manifest artifact"},
		{"日志哈希链", yesNo(view.chainOK), "prev_hash / entry_hash"},
		{"证据哈希", yesNo(view.artifactsOK), "stored sha256"},
		{"触发位置", yesNo(view.record.Trigger.File != "" && view.record.Trigger.Line > 0), view.record.Trigger.String()},
	}
}

func yesNo(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func cell(value any) string {
	text := strings.ReplaceAll(fmt.Sprint(value), "|", `\|`)
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	return text
}

func code(value any) string {
	return "`" + strings.ReplaceAll(fmt.Sprint(value), "`", "'") + "`"
}

func shortHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16]
}

func statusLabel(status model.RunStatus) string {
	switch status {
	case model.StatusRunning:
		return "RUNNING / 未完成，需处置"
	case model.StatusAllowed:
		return "ALLOWED / 已提交"
	case model.StatusDenied:
		return "DENIED / 未执行"
	case model.StatusCancelled:
		return "CANCELLED / 已回滚"
	case model.StatusFailed:
		return "FAILED / 需处置"
	default:
		return string(status)
	}
}

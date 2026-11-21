package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"pathaliaslab/internal/model"
)

func renderMarkdown(report Report) string {
	var out strings.Builder
	out.WriteString("# 路径别名冲突：可回放实验报告\n\n")
	fmt.Fprintf(&out, "- 生成时间（UTC）：`%s`\n", report.GeneratedAtUTC)
	fmt.Fprintf(&out, "- 总体状态：**%s**\n", report.OverallStatus)
	fmt.Fprintf(&out, "- 技术栈：`%s` · SQLite `%s` · libFuzzer\n", report.Runtime.GoVersion, report.Runtime.SQLiteVersion)
	fmt.Fprintf(&out, "- SQLite 证据库：`%s`\n", report.Evidence.DatabasePath)
	fmt.Fprintf(&out, "- 数据库 SHA-256：`%s`\n\n", report.Evidence.DatabaseSHA256)
	out.WriteString("> 自动结论只陈述机器断言覆盖的事实。产品语义、保留策略和规范解释列在“人工确认”，未自动判定。\n\n")

	out.WriteString("## 自动结论\n\n")
	out.WriteString("| ID | 状态 | 结论 | 证据 |\n|---|---|---|---|\n")
	for _, conclusion := range report.AutomaticConclusions {
		fmt.Fprintf(&out, "| %s | %s | %s | %s |\n",
			conclusion.ID, conclusionLabel(conclusion.Status),
			tableText(conclusion.Statement), tableText(conclusion.Evidence))
	}

	out.WriteString("\n## 实验矩阵\n\n")
	out.WriteString("| 运行 | 角色 | 状态 | 步数 | 最终解析摘要 | 证据链头 |\n|---|---|---|---:|---|---|\n")
	for _, run := range report.Runs {
		fmt.Fprintf(&out, "| `%s` | %s | %s | %d | `%s` | `%s` |\n",
			run.RunID, run.Role, run.Status, run.StepCount,
			shortHash(run.ResolutionSHA256), shortHash(run.EventSHA256))
	}

	out.WriteString("\n## 每步证据\n\n")
	for _, run := range report.Runs {
		fmt.Fprintf(&out, "### `%s`\n\n", run.RunID)
		out.WriteString("| # | 操作 | 输入 | 状态摘要（前） | 结果 | 状态摘要（后） | 证据 SHA-256 |\n")
		out.WriteString("|---:|---|---|---|---|---|---|\n")
		for _, step := range run.Steps {
			fmt.Fprintf(&out, "| %d | `%s` | %s | `%s` | %s | `%s` | `%s` |\n",
				step.StepNo, step.OpID, tableText(compactInput(step.Input)),
				shortHash(step.StateBeforeSHA256), tableText(compactResult(step.RecordedResult)),
				shortHash(step.StateAfterSHA256), shortHash(step.EvidenceSHA256))
		}
		fmt.Fprintf(&out, "\n完整输入与前后状态：`artifacts/evidence/runs/%s.jsonl`。\n\n", run.RunID)
	}

	out.WriteString("## 回放校验\n\n")
	out.WriteString("| 源运行 | 回放运行 | 输入一致 | 状态一致 | 结果一致 | 判定 | 说明 |\n|---|---|---|---|---|---|---|\n")
	for _, replay := range report.Replays {
		fmt.Fprintf(&out, "| `%s` | `%s` | %s | %s | %s | %s | %s |\n",
			replay.SourceRunID, replay.ReplayRunID, yesNo(replay.InputMatch),
			yesNo(replay.StateMatch), yesNo(replay.ResultMatch), passLabel(replay.Passed),
			tableText(replay.Detail))
	}

	out.WriteString("\n## libFuzzer\n\n")
	fmt.Fprintf(&out, "- 状态：**%s**\n", report.Fuzz.Status)
	fmt.Fprintf(&out, "- 执行次数：`%d`\n", report.Fuzz.Executions)
	fmt.Fprintf(&out, "- corpus 文件数：`%d`\n", report.Fuzz.CorpusFiles)
	fmt.Fprintf(&out, "- 日志：`%s`\n", report.Fuzz.LogPath)
	fmt.Fprintf(&out, "- 二进制：`%s`\n", report.Fuzz.BinaryPath)
	fmt.Fprintf(&out, "- 失败工件数：`%d`\n", len(report.Fuzz.CrashArtifacts))
	if report.Fuzz.Detail != "" {
		fmt.Fprintf(&out, "- 最后一行日志：`%s`\n", tableText(report.Fuzz.Detail))
	}

	out.WriteString("\n## 人工确认\n\n")
	out.WriteString("以下项目保持 `pending`，自动实验不能替代人工决策。\n\n")
	for _, item := range report.ManualConfirmations {
		fmt.Fprintf(&out, "- [ ] **%s** %s\n", item.ID, item.Question)
		fmt.Fprintf(&out, "  - 原因：%s\n", item.Why)
		fmt.Fprintf(&out, "  - 证据：%s\n", item.Evidence)
	}

	out.WriteString("\n## 失败后续操作\n\n")
	out.WriteString("以下命令可直接执行；失败时按顺序运行并保留输出。\n\n")
	out.WriteString("| 触发条件 | 命令 | 目的 |\n|---|---|---|\n")
	for _, action := range report.FailureActions {
		fmt.Fprintf(&out, "| %s | `%s` | %s |\n",
			tableText(action.Condition), action.Command, tableText(action.Purpose))
	}

	out.WriteString("\n## 检查清单\n\n")
	out.WriteString("| 范围 | 检查 | 结果 | 期望 | 实际 |\n|---|---|---|---|---|\n")
	checks := append([]CheckSummary(nil), report.Checks...)
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].RunID == checks[j].RunID {
			return checks[i].Name < checks[j].Name
		}
		return checks[i].RunID < checks[j].RunID
	})
	for _, check := range checks {
		fmt.Fprintf(&out, "| `%s` | `%s` | %s | %s | %s |\n",
			check.RunID, check.Name, passLabel(check.Passed),
			tableText(check.Expected), tableText(check.Actual))
	}

	out.WriteString("\n## 证据文件\n\n")
	fmt.Fprintf(&out, "- 证据清单：`artifacts/evidence/manifest.json`\n")
	fmt.Fprintf(&out, "- 全量运行记录：`artifacts/evidence/runs.json`\n")
	fmt.Fprintf(&out, "- 检查结果：`artifacts/evidence/checks.json`\n")
	fmt.Fprintf(&out, "- SQLite 证据库：`%s`\n", report.Evidence.DatabasePath)
	fmt.Fprintf(&out, "- SQLite 完整性：`%s`\n", strings.Join(report.Evidence.Integrity, ", "))
	return out.String()
}

func compactInput(raw string) string {
	var op model.Op
	if err := json.Unmarshal([]byte(raw), &op); err != nil {
		return raw
	}
	if op.Kind == model.OpCancel {
		return fmt.Sprintf("cancel %s", op.CancelID)
	}
	return fmt.Sprintf("%s -> %s", op.Alias, op.Target)
}

func compactResult(raw string) string {
	var result model.Result
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return raw
	}
	if len(result.ConflictWith) > 0 {
		return fmt.Sprintf("%s, conflict with %s", result.Outcome, strings.Join(result.ConflictWith, ","))
	}
	return result.Outcome
}

func conclusionLabel(status string) string {
	if status == "confirmed" {
		return "已确认"
	}
	return "失败"
}

func passLabel(value bool) string {
	if value {
		return "PASS"
	}
	return "FAIL"
}

func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func tableText(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	if len(value) > 160 {
		return value[:157] + "..."
	}
	return value
}

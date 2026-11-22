package report

import (
	"fmt"
	"strings"
)

func Markdown(report Report) string {
	var out strings.Builder
	out.WriteString("# 随机数种子审查报告\n\n")
	writeRunSummary(&out, report)
	writeAutomatic(&out, report)
	writeManual(&out, report)
	writeFailure(&out, report)
	writeAuditTrail(&out, report)
	writeCompatibility(&out, report)
	return out.String()
}

func writeRunSummary(out *strings.Builder, report Report) {
	out.WriteString("## 主线：恢复后的一次重放\n\n")
	out.WriteString("| 项目 | 值 |\n|---|---|\n")
	fmt.Fprintf(out, "| Run ID | `%d` |\n", report.Run.ID)
	fmt.Fprintf(out, "| 恢复会话 | `%s` |\n", markdownEscape(report.Run.RecoveryID))
	fmt.Fprintf(out, "| 输入清单格式 | `%s` |\n", markdownEscape(report.Run.SourceFormat))
	fmt.Fprintf(out, "| 应用版本 | `%s` |\n", markdownEscape(report.Run.AppVersion))
	fmt.Fprintf(out, "| 随机数算法 | `%s` |\n", markdownEscape(report.Run.RNGAlgorithm))
	fmt.Fprintf(out, "| 恢复种子 / 重放有效种子 | `%s` / `%s` |\n",
		markdownEscape(report.Run.RecoveredSeed),
		markdownEscape(report.Run.EffectiveSeed))
	fmt.Fprintf(out, "| 恢复时间 | `%s` |\n", markdownEscape(report.Run.CapturedAt))
	fmt.Fprintf(out, "| 重放时间 | `%s` 至 `%s` |\n",
		markdownEscape(report.Run.StartedAt), markdownEscape(report.Run.CompletedAt))
	fmt.Fprintf(out, "| 重放目标 | `%s` (`%s`) |\n",
		markdownEscape(report.Automatic.Mapping.AttackInput.TargetPath),
		shortHash(report.Automatic.Mapping.AttackInput.TargetSHA256))
	fmt.Fprintf(out, "| 重放状态 | `%s` |\n\n", markdownEscape(report.Run.Status))
}

func writeAutomatic(out *strings.Builder, report Report) {
	automatic := report.Automatic
	out.WriteString("## 自动结论\n\n")
	out.WriteString("> 本节由工具根据重放 trace 与证据哈希生成，不代表人工批准。\n\n")
	fmt.Fprintf(out, "- 结论代码：`%s`\n", markdownEscape(automatic.Conclusion))
	fmt.Fprintf(out, "- 结论摘要：%s\n", automatic.ConclusionText)
	integrity := "通过"
	if !automatic.EvidenceIntegrity.OK {
		integrity = "失败"
	}
	fmt.Fprintf(out, "- 证据完整性：`%s`\n\n", integrity)

	out.WriteString("### 证据对应关系\n\n")
	out.WriteString("| 环节 | 值 | 证据 |\n|---|---|---|\n")
	input := automatic.Mapping.AttackInput
	fmt.Fprintf(out, "| 攻击输入 | size=%d `%s` | evidence `%s`, target `%s` |\n",
		input.Size, shortHash(input.SHA256), shortHash(input.EvidenceSHA256),
		shortHash(input.TargetSHA256))
	if extension := automatic.Mapping.UnknownExtension; extension != nil {
		fmt.Fprintf(out, "| 未知扩展 | `%s` | trace start event |\n",
			markdownEscape(extension.Name))
	} else {
		out.WriteString("| 未知扩展 | 未记录 | trace start event |\n")
	}
	if trigger := automatic.Mapping.Trigger; trigger != nil {
		fmt.Fprintf(out, "| 触发位置 | `%s:%d` `%s` | trace trigger `%s` |\n",
			markdownEscape(trigger.File), trigger.Line,
			markdownEscape(trigger.Function), markdownEscape(trigger.Kind))
	} else {
		out.WriteString("| 触发位置 | 未记录 | trace trigger |\n")
	}
	if permission := automatic.Mapping.Permission; permission != nil {
		fmt.Fprintf(out,
			"| 权限判断 | `%s` by `%s`; policy `%s`; reason %s | expected `%s`, actual `%s` |\n",
			markdownEscape(permission.Action), markdownEscape(permission.Principal),
			markdownEscape(permission.Policy), markdownEscape(permission.Reason),
			markdownEscape(permission.Expected), markdownEscape(permission.Actual))
	} else {
		out.WriteString("| 权限判断 | 未记录 | trace permission |\n")
	}
	if len(automatic.Mapping.Logs) == 0 {
		out.WriteString("| 日志证据 | 未提取到关键日志 | stderr evidence |\n")
	} else {
		for index, line := range automatic.Mapping.Logs {
			label := "日志证据"
			if index > 0 {
				label = ""
			}
			fmt.Fprintf(out, "| %s | `%s` %s | line `%s` |\n",
				label, line.Level, markdownEscape(line.Message),
				shortHash(line.LineSHA256))
		}
	}
	out.WriteString("\n### 自动发现\n\n")
	if len(automatic.Findings) == 0 {
		out.WriteString("- 无自动发现。\n\n")
	} else {
		for _, finding := range automatic.Findings {
			fmt.Fprintf(out, "- `%s` [%s] %s\n",
				finding.Code, finding.Severity, finding.Title)
		}
		out.WriteString("\n")
	}
	out.WriteString("### 证据校验\n\n")
	out.WriteString("| 类型 | 哈希 | 状态 |\n|---|---|---|\n")
	for _, item := range automatic.EvidenceIntegrity.Items {
		status := "ok"
		if !item.HashOK {
			status = "FAIL: " + markdownEscape(item.Error)
		}
		fmt.Fprintf(out, "| `%s` | `%s` | %s |\n",
			item.Kind, shortHash(item.SHA256), status)
	}
	out.WriteString("\n")
}

func writeManual(out *strings.Builder, report Report) {
	manual := report.Manual
	out.WriteString("## 人工确认\n\n")
	out.WriteString("> 本节是独立人工判断，不被自动结论替代。\n\n")
	fmt.Fprintf(out, "- 确认状态：`%s`\n", manual.Status)
	fmt.Fprintf(out, "- 待确认项：`%d`\n\n", manual.Pending)
	out.WriteString("| 状态 | 代码 | 必须确认的问题 | 负责人 | 备注 |\n")
	out.WriteString("|---|---|---|---|---|\n")
	for _, check := range manual.Checks {
		required := "否"
		if check.Required {
			required = "是"
		}
		fmt.Fprintf(out, "| `%s` | `%s` | %s（必须：%s） | %s | %s |\n",
			check.Status, check.Code, markdownEscape(check.Question),
			required, markdownEscape(check.Owner), markdownEscape(check.Notes))
	}
	out.WriteString("\n")
}

func writeFailure(out *strings.Builder, report Report) {
	automatic := report.Automatic
	out.WriteString("## 失败后续操作\n\n")
	if automatic.Failure.Code == "" && automatic.EvidenceIntegrity.OK {
		out.WriteString("本次重放与证据校验未触发失败处置。\n\n")
		return
	}
	if automatic.Failure.Code != "" {
		fmt.Fprintf(out, "- 失败代码：`%s`\n", automatic.Failure.Code)
		fmt.Fprintf(out, "- 失败信息：%s\n\n", markdownEscape(automatic.Failure.Message))
	}
	if !automatic.EvidenceIntegrity.OK {
		out.WriteString("- 证据完整性失败：先恢复缺失或损坏的证据，再重新生成报告。\n\n")
	}
	if len(automatic.Failure.NextActions) == 0 {
		out.WriteString("1. 运行 `seedreview verify`，确认证据哈希后重新生成报告。\n\n")
		return
	}
	for index, action := range automatic.Failure.NextActions {
		fmt.Fprintf(out, "%d. `%s`：%s\n   - 原因：%s\n",
			index+1, action.Code, action.Action, action.Reason)
	}
	out.WriteString("\n")
}

func writeAuditTrail(out *strings.Builder, report Report) {
	out.WriteString("## 审计记录\n\n")
	if len(report.AuditTrail) == 0 {
		out.WriteString("无审计事件。\n\n")
		return
	}
	out.WriteString("| 时间 | 操作者 | 事件 |\n|---|---|---|\n")
	for _, event := range report.AuditTrail {
		fmt.Fprintf(out, "| `%s` | `%s` | `%s` |\n",
			markdownEscape(stringValue(event["at"])),
			markdownEscape(stringValue(event["actor"])),
			markdownEscape(stringValue(event["action"])))
	}
	out.WriteString("\n")
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func writeCompatibility(out *strings.Builder, report Report) {
	out.WriteString("## 复核与兼容性\n\n")
	fmt.Fprintf(out, "- 输入格式：`%s`\n", report.Compatibility.InputFormat)
	fmt.Fprintf(out, "- 输出格式：`%s`\n", report.Compatibility.OutputFormat)
	fmt.Fprintf(out, "- 人工确认命令：`seedreview manual --db <db> --run %d --check <code> --status confirmed --owner <name>`\n",
		report.Run.ID)
	fmt.Fprintf(out, "- 证据校验命令：`seedreview verify --db <db> --evidence <dir>`\n")
	fmt.Fprintf(out, "- JSON 复核命令：`seedreview report --db <db> --run %d --format json`\n",
		report.Run.ID)
}

func shortHash(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16]
}

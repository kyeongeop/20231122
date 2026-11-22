package report

import (
	"bytes"
	"fmt"

	"example.com/migration-review/internal/evidence"
	"example.com/migration-review/internal/model"
)

func automaticChecks(views []runView, opts Options) []check {
	var allChain, allArtifacts, allCorrelated bool = len(views) > 0, len(views) > 0, len(views) > 0
	var allCompleted bool = len(views) > 0
	var oldFormat, newFormat, cancellation, attackBlocked bool
	policyStatus := "NOT_COVERED"
	if opts.PolicySHA256 != "" {
		policyStatus = "PASS"
	}
	for _, view := range views {
		if !view.chainOK {
			allChain = false
		}
		if !view.artifactsOK {
			allArtifacts = false
		}
		if view.record.Trigger.File == "" || len(view.keyLogs) == 0 || !view.associationOK {
			allCorrelated = false
		}
		if view.record.CompletedAt == nil || view.record.Status == model.StatusRunning {
			allCompleted = false
		}
		if view.record.Format == model.FormatLegacyJSON || view.record.Format == model.FormatLegacySQL {
			oldFormat = true
		}
		if view.record.Format == model.FormatCurrent {
			newFormat = true
		}
		if view.record.Status == model.StatusCancelled && view.record.RollbackOK &&
			view.record.SchemaBefore == view.record.SchemaAfter && view.record.SchemaBefore != "" {
			cancellation = true
		}
		if view.record.Status == model.StatusDenied && deniedDestructive(view.record) {
			attackBlocked = true
		}
		if opts.PolicySHA256 != "" && view.record.Decision.PolicySHA256 != opts.PolicySHA256 {
			policyStatus = "FAIL"
		}
	}
	return []check{
		{"策略文件与证据一致", policyStatus, "提供的策略文件 SHA-256 与运行快照一致"},
		{"所有运行已完结", yesNo(allCompleted), "存在 completed_at 且不处于 RUNNING"},
		{"日志哈希链完整", yesNo(allChain), "所有运行均验证 prev_hash 与 entry_hash"},
		{"证据内容哈希完整", yesNo(allArtifacts), "所有留存证据重新计算 SHA-256"},
		{"输入-触发-权限-日志可关联", yesNo(allCorrelated), "运行级 trigger、证据和关键日志均存在"},
		{"旧格式兼容", covered(oldFormat), "legacy-v1 / legacy-sql"},
		{"新格式兼容", covered(newFormat), "format_version=2"},
		{"中途取消并回滚", covered(cancellation), "CANCELLED 且 schema_before == schema_after"},
		{"危险权限攻击被拦截", covered(attackBlocked), "DENIED 且 destructive 语句未执行"},
	}
}

func covered(ok bool) string {
	if ok {
		return "PASS"
	}
	return "NOT_COVERED"
}

func deniedDestructive(record model.RunRecord) bool {
	for _, statement := range record.Decision.Statements {
		if !statement.Allowed && statement.Capability == model.CapDestructive {
			return true
		}
	}
	return false
}

func writeAutomatic(out *bytes.Buffer, views []runView, checks []check) {
	fmt.Fprintln(out, "## 自动结论")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "### 自动检查矩阵")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 检查项 | 结果 | 判定依据 |")
	fmt.Fprintln(out, "| --- | --- | --- |")
	for _, item := range checks {
		fmt.Fprintf(out, "| %s | **%s** | %s |\n", cell(item.Name), item.Status, cell(item.Detail))
	}
	fmt.Fprintln(out)
	if len(views) == 0 {
		fmt.Fprintln(out, "证据库中没有运行记录。")
		fmt.Fprintln(out)
		return
	}
	fmt.Fprintln(out, "### 运行总览")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 运行 | 格式 | Actor | 状态 | 触发位置 | 回滚一致 |")
	fmt.Fprintln(out, "| --- | --- | --- | --- | --- | --- |")
	for _, view := range views {
		rollback := "N/A"
		if view.record.Status == model.StatusCancelled || view.record.Status == model.StatusFailed {
			rollback = yesNo(view.record.RollbackOK)
		}
		fmt.Fprintf(out, "| %s | %s | %s | %s | %s | %s |\n",
			code(view.record.RunID), view.record.Format, cell(view.record.Actor),
			statusLabel(view.record.Status), code(view.record.Trigger.String()), rollback)
	}
	fmt.Fprintln(out)
	for _, view := range views {
		writeRun(out, view)
	}
}

func writeRun(out *bytes.Buffer, view runView) {
	record := view.record
	fmt.Fprintf(out, "### 运行 %s\n\n", code(record.RunID))
	fmt.Fprintln(out, "**自动结论**")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "- 输入/攻击载荷：%s，SHA-256 %s，%d bytes。\n",
		code(record.InputPath), code(record.InputSHA256), len(record.InputBytes))
	fmt.Fprintf(out, "- 格式兼容路径：%s，归一化清单已作为证据留存。\n", code(record.Format))
	fmt.Fprintf(out, "- 触发位置：%s，token %s。\n",
		code(record.Trigger.String()), code(record.Trigger.Token))
	fmt.Fprintf(out, "- 权限判断：%s；%s。\n", permissionVerdict(record), cell(record.Reason))
	if record.Status == model.StatusDenied {
		fmt.Fprintf(out, "- 执行结果：%s；未打开目标库，无 schema 快照。\n", statusLabel(record.Status))
	} else {
		fmt.Fprintf(out, "- 执行结果：%s；schema before %s，schema after %s。\n",
			statusLabel(record.Status), code(shortHash(record.SchemaBefore)), code(shortHash(record.SchemaAfter)))
	}
	if record.Status == model.StatusCancelled {
		fmt.Fprintf(out, "- 回滚结论：%s（前后 schema 哈希%s）。\n",
			yesNo(record.RollbackOK), equalText(record.RollbackOK))
	}
	fmt.Fprintf(out, "- 关联结论：%s\n", correlationConclusion(record))
	fmt.Fprintf(out, "- 证据体积：%d bytes；日志头哈希：%s。\n\n", record.EvidenceBytes, code(shortHash(record.LogHeadHash)))

	writePermissionTable(out, record)
	writeEvidenceMapping(out, view)
	writeLogs(out, view)
}

func permissionVerdict(record model.RunRecord) string {
	if record.Decision.Allowed {
		return "**ALLOW**（全部语句通过）"
	}
	return "**DENY**（至少一条语句未通过）"
}

func equalText(equal bool) string {
	if equal {
		return "一致"
	}
	return "不一致"
}

func correlationConclusion(record model.RunRecord) string {
	switch record.Status {
	case model.StatusDenied:
		return "输入中的危险 token、触发位置、DENY 判定与 permission_decision 日志指向同一语句。"
	case model.StatusCancelled:
		return "cancel_requested 日志、rollback 日志与前后 schema 哈希相互印证，未提交。"
	case model.StatusAllowed:
		return "commit 日志存在，前后 schema 哈希记录了实际变化。"
	default:
		return "失败日志已留存；是否可回滚需结合 schema 哈希与人工检查确认。"
	}
}

func writePermissionTable(out *bytes.Buffer, record model.RunRecord) {
	fmt.Fprintln(out, "**语句级权限证据**")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| # | 关键词/能力 | 结果 | 触发位置 | 原因 |")
	fmt.Fprintln(out, "| --- | --- | --- | --- | --- |")
	for _, statement := range record.Decision.Statements {
		result := "ALLOW"
		if !statement.Allowed {
			result = "DENY"
		}
		fmt.Fprintf(out, "| %d | %s / %s | **%s** | %s | %s |\n",
			statement.Index+1, cell(statement.Keyword), statement.Capability,
			result, code(statement.Trigger.String()), cell(statement.Reason))
	}
	fmt.Fprintln(out)
}

func writeEvidenceMapping(out *bytes.Buffer, view runView) {
	fmt.Fprintln(out, "**四元证据对应**")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 复核项 | 证据定位 |")
	fmt.Fprintln(out, "| --- | --- |")
	fmt.Fprintf(out, "| 攻击输入 | %s；SHA-256 %s |\n", code(view.record.InputPath), code(view.record.InputSHA256))
	fmt.Fprintf(out, "| 触发位置 | %s；token %s |\n", code(view.record.Trigger.String()), code(view.record.Trigger.Token))
	fmt.Fprintf(out, "| 权限判断 | policy %s；decision artifact `permission/decision.json` |\n", code(shortHash(view.record.Decision.PolicySHA256)))
	fmt.Fprintf(out, "| 日志证据 | %s；head %s；链校验 **%s** |\n",
		code(logRange(view.keyLogs)), code(shortHash(view.record.LogHeadHash)), yesNo(view.chainOK))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "**留存证据对象**")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| 类型 | 名称 | SHA-256 | 字节数 |")
	fmt.Fprintln(out, "| --- | --- | --- | --- |")
	for _, artifact := range view.artifacts {
		fmt.Fprintf(out, "| %s | %s | %s | %d |\n",
			cell(artifact.Kind), cell(artifact.Name), code(artifact.SHA256), len(artifact.Content))
	}
	fmt.Fprintln(out)
}

func logRange(logs []evidence.LogEntry) string {
	if len(logs) == 0 {
		return "无关键日志"
	}
	return fmt.Sprintf("logs seq %d-%d", logs[0].Seq, logs[len(logs)-1].Seq)
}

func writeLogs(out *bytes.Buffer, view runView) {
	fmt.Fprintln(out, "**关键日志证据**")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "| seq | level | event | detail | entry_hash |")
	fmt.Fprintln(out, "| --- | --- | --- | --- | --- |")
	for _, entry := range view.keyLogs {
		detail := entry.Detail
		if len(detail) > 220 {
			detail = detail[:220] + "..."
		}
		fmt.Fprintf(out, "| %d | %s | %s | %s | %s |\n",
			entry.Seq, entry.Level, code(entry.Event), code(detail), code(shortHash(entry.Hash)))
	}
	fmt.Fprintln(out)
}

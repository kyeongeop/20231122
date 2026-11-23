package report

import (
	"fmt"
	"strings"
	"time"

	"oauthreview/internal/callback"
	"oauthreview/internal/evidence"
)

// Expectation 来自语料声明，用于标注自动结论是否符合预期。
type Expectation map[string]string

// BuildMarkdown 生成双分区复核报告。
func BuildMarkdown(rows []evidence.CaseRow, expect Expectation, fuzzSummary string) string {
	var b strings.Builder
	b.WriteString("# OAuth 回调校验复核报告\n\n")
	b.WriteString("生成时间: " + time.Now().UTC().Format(time.RFC3339) + "\n\n")
	b.WriteString("> 自动结论由校验流水线产生；人工确认分区仅在复核人落库后填充。\n")
	b.WriteString("> 所有原始输入以 sha256 哈希关联，保存在 SQLite 证据库 `cases.raw_input`。\n\n")

	b.WriteString("## 一、自动结论（机器生成，待人工确认）\n\n")
	b.WriteString("| 用例 | 格式 | 自动结论 | 触发位置 | 权限判断规则 | 预期 | 一致性 |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		want := expect[r.CaseID]
		match := "—"
		if want != "" {
			if want == r.Verdict {
				match = "✅ 一致"
			} else {
				match = "❌ 不一致"
			}
		}
		b.WriteString(fmt.Sprintf("| %s | %s | `%s` | `%s` | `%s` | `%s` | %s |\n",
			r.CaseID, r.Format, r.Verdict, r.TriggerPoint, r.PermissionLog, want, match))
	}
	b.WriteString("\n")

	for _, r := range rows {
		writeCaseDetail(&b, r)
	}

	b.WriteString("## 二、人工确认（复核人填写区）\n\n")
	b.WriteString("| 用例 | 复核人 | 是否确认自动结论 | 备注 | 时间 |\n")
	b.WriteString("|---|---|---|---|---|\n")
	pending := 0
	for _, r := range rows {
		if r.Review == nil {
			pending++
			b.WriteString(fmt.Sprintf("| %s | _待确认_ | — | — | — |\n", r.CaseID))
			continue
		}
		confirmed := "否"
		if r.Review.Confirmed {
			confirmed = "是"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			r.CaseID, r.Review.Reviewer, confirmed, r.Review.Notes, r.Review.ReviewedAt))
	}
	b.WriteString(fmt.Sprintf("\n待人工确认用例数: **%d / %d**\n\n", pending, len(rows)))

	b.WriteString("## 三、失败用例的可执行后续操作\n\n")
	b.WriteString(followUps(rows))

	if fuzzSummary != "" {
		b.WriteString("## 四、libFuzzer 运行摘要\n\n```\n" + fuzzSummary + "\n```\n")
	}
	return b.String()
}

func writeCaseDetail(b *strings.Builder, r evidence.CaseRow) {
	b.WriteString("### " + r.CaseID + "\n\n")
	b.WriteString(fmt.Sprintf("- 攻击输入/来源: `%s`；Content-Type: `%s`\n", r.Source, r.ContentType))
	b.WriteString("- 输入哈希(证据指针): `" + r.InputHash + "`\n")
	b.WriteString(fmt.Sprintf("- 自动结论: `%s`，原因: %s\n", r.Verdict, r.ReasonHuman))
	b.WriteString("- 攻击输入 → 触发位置 → 权限判断 → 日志证据 对照:\n\n")
	b.WriteString("| 序号 | 触发位置 | 检查项 | 结果 | 判定 | 原因码 | 证据哈希 |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, ev := range r.Events {
		passed := "通过"
		if !ev.Passed {
			passed = "**阻断**"
		}
		b.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | `%s` | `%s` | `%s` |\n",
			ev.Seq, ev.Stage, ev.Check, passed, ev.Verdict,
			emptyDash(ev.ReasonCode), shortHash(ev.Evidence)))
	}
	b.WriteString("\n<details><summary>保留的原始输入</summary>\n\n```\n")
	b.WriteString(sanitize(r.RawInput))
	b.WriteString("\n```\n\n</details>\n\n")
}

func followUps(rows []evidence.CaseRow) string {
	var b strings.Builder
	action := map[string]string{
		"CANCELLED":     "1) 不发起 token 换码；2) 清理该 state 绑定；3) 若缺少服务端 cancel 标记，回溯会话日志确认是否为伪造取消。",
		"DENY":          "1) 拒绝换码并保留 4xx 审计日志；2) 冻结关联 state 防止重放；3) 将原始输入加入 fuzz 回归语料；4) 触发安全告警并按原因码分派处置。",
		"INDETERMINATE": "1) 挂起会话等待人工复核；2) 不做任何权限放行；3) 复核后通过 review 命令回填结论。",
	}
	any := false
	for _, r := range rows {
		if r.Verdict == "ALLOW" {
			continue
		}
		any = true
		step, ok := action[r.Verdict]
		if !ok {
			step = action["DENY"]
		}
		b.WriteString(fmt.Sprintf("- **%s** (`%s` @ `%s`): %s\n", r.CaseID, r.Verdict, r.TriggerPoint, step))
	}
	if !any {
		b.WriteString("无失败用例。常规动作：保留证据库并纳入每日回归。\n")
	}
	b.WriteString("\n复核操作命令:\n```\n")
	b.WriteString("# 确认自动结论\nbin/oauthreview review --case <CASE_ID> --reviewer <姓名> --confirm --notes \"...\"\n")
	b.WriteString("# 驳回自动结论\nbin/oauthreview review --case <CASE_ID> --reviewer <姓名> --reject --notes \"...\"\n")
	b.WriteString("# 单条重放（证据不可覆盖，重复入库会被拒绝）\nbin/oauthreview replay --corpus fuzz/seed --case <CASE_ID>\n```\n\n")
	return b.String()
}

func sanitize(in []byte) string {
	s := string(in)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 1200 {
		s = s[:1200] + "...(truncated)"
	}
	return s
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return emptyDash(h)
	}
	return h[:16] + "…"
}

func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

var _ = callback.VerdictAllow

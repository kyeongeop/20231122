package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const sampleLog = `2026-11-22T20:39:58.102Z INFO  edge.request id=req_7Q2F method=POST path=/v1/export remote=10.24.8.17
2026-11-22T20:39:58.104Z INFO  edge.route   upstream=export-api route=export-v2 tls=1.3
2026-11-22T20:39:58.109Z WARN  edge.quote   field="user-agent" value="Mozilla/5.0 %0d%0a2026-11-22T20:40:01.000Z INFO audit actor=admin action=export status=ok"
2026-11-22T20:39:58.110Z INFO  edge.quote   field="x-partner" value="alpha\u2028beta"
2026-11-22T20:39:58.111Z INFO  edge.response status=200 bytes=1842 duration=12ms
`

func (s *Store) seed(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM checks`).Scan(&count); err != nil {
		return fmt.Errorf("count checks: %w", err)
	}
	if count > 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := seedCheck(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func seedCheck(ctx context.Context, tx *sql.Tx) error {
	const checkID = "CHK-1A7F"
	created := mustTime("2026-11-22T20:39:58+08:00")
	humanAt := mustTime("2026-11-22T21:08:42+08:00")
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO checks (
			id, title, source, input_name, raw_input, raw_sha256, created_at, status,
			auto_verdict, auto_label, confidence, auto_summary, ambiguous_rule, ambiguous_note,
			human_verdict, human_label, human_reviewer, human_note, human_at,
			fuzzer_version, fuzzer_execs, fuzzer_artifact
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		checkID, "网关访问日志 · 注入来源检查", "edge-gateway / prod-cn-east",
		"gateway_access_2026-11-22T20-39-58Z.log", []byte(sampleLog), Hash([]byte(sampleLog)),
		created.Format(time.RFC3339Nano), "completed",
		"malicious", "高风险 · 日志注入", 0.93,
		"在 user-agent 引用字段中发现可解码的 CRLF 序列，可伪造独立审计日志行。",
		"BOUNDARY-07", "U+2028 位于带引号字段内；上游解析器版本不同，无法确认其是否被当作行分隔符。",
		"confirmed", "已确认注入", "周雪 · 安全运营",
		"已核对上游原始请求：CRLF 由 user-agent 字段带入。U+2028 不构成独立注入，但主证据成立。已创建处置单 SEC-4821。",
		humanAt.Format(time.RFC3339Nano),
		"libFuzzer / LLVM 20.1.8", 182204, "8b0ce4a91f72c8d91a",
	); err != nil {
		return fmt.Errorf("insert check: %w", err)
	}

	if err := seedAttempts(ctx, tx, checkID); err != nil {
		return err
	}
	if err := seedFindings(ctx, tx, checkID); err != nil {
		return err
	}
	if err := seedAudits(ctx, tx, checkID); err != nil {
		return err
	}
	return nil
}

func seedAttempts(ctx context.Context, tx *sql.Tx, checkID string) error {
	type attemptSeed struct {
		id, status, start, end, by, reason, code, message string
		actions                                           []string
		evidence                                          int
	}
	attempts := []attemptSeed{
		{
			id: "CHK-1A7F-A01", status: "cancelled",
			start: "2026-11-22T20:40:02+08:00", end: "2026-11-22T20:40:18+08:00",
			by:       "林澈 · 当班分析员",
			reason:   "发现输入含疑似生产令牌，主动中止以避免证据扩散；原始文件已留存。",
			evidence: 2,
		},
		{
			id: "CHK-1A7F-A02", status: "cancelled",
			start: "2026-11-22T20:40:31+08:00", end: "2026-11-22T20:40:49+08:00",
			by:       "控制台 · 自动取消",
			reason:   "上游采集连接中断，传入输入不完整；在行边界关联前终止本次尝试。",
			evidence: 3,
		},
		{
			id: "CHK-1A7F-A03", status: "failed",
			start: "2026-11-22T20:41:12+08:00", end: "2026-11-22T20:41:31+08:00",
			code: "SQLITE_BUSY", message: "证据写入冲突：数据库被另一个 fuzz worker 长时间锁定。已完成的前 3 步和部分证据仍保留。",
			actions: []string{
				"确认 SQLite 已启用 WAL 与 5s busy_timeout，然后仅从失败步骤重试。",
				"检查磁盘余量：df -h 与 sqlite3 data/tracecheck.db 'PRAGMA integrity_check;'。",
				"若冲突持续，导出部分证据并附 trace ID CHK-1A7F-A03 交由平台值班处理。",
			},
			evidence: 3,
		},
		{
			id: "CHK-1A7F-A04", status: "completed",
			start: "2026-11-22T20:42:05+08:00", end: "2026-11-22T20:42:18+08:00",
			evidence: 5,
		},
	}
	for i, a := range attempts {
		actions, _ := json.Marshal(a.actions)
		var end any
		if a.end != "" {
			end = a.end
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO attempts (id, check_id, number, status, started_at, ended_at,
				cancelled_by, cancel_reason, error_code, error_message, next_actions, evidence_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.id, checkID, i+1, a.status, a.start, end, a.by, a.reason, a.code, a.message,
			string(actions), a.evidence,
		); err != nil {
			return fmt.Errorf("insert attempt %s: %w", a.id, err)
		}
	}
	if err := seedSteps(ctx, tx, checkID); err != nil {
		return err
	}
	return seedEvidence(ctx, tx, checkID)
}

func seedSteps(ctx context.Context, tx *sql.Tx, checkID string) error {
	type stepSeed struct {
		id, attempt, phase, title, status, start, end, summary string
		input, output, tool                                    string
		evidence                                               []string
		ambiguous                                              bool
	}
	steps := []stepSeed{
		{
			id: "CHK-1A7F-A01-S1", attempt: "CHK-1A7F-A01", phase: "ingest",
			title: "接收与指纹", status: "completed",
			start: "2026-11-22T20:40:02+08:00", end: "2026-11-22T20:40:03+08:00",
			summary: "原始文件读取完成，SHA-256 与采集端声明一致。",
			input:   "gateway_access_2026-11-22T20-39-58Z.log · 612 B",
			output:  "sha256:c39f2e0a…b45a · 原始字节保持不变", tool: "sha256sum",
			evidence: []string{"E-101"},
		},
		{
			id: "CHK-1A7F-A01-S2", attempt: "CHK-1A7F-A01", phase: "normalize",
			title: "编码与换行规范化", status: "cancelled",
			start: "2026-11-22T20:40:03+08:00", end: "2026-11-22T20:40:18+08:00",
			summary: "收到人工取消信号；已生成规范化前快照，未继续处理。",
			input:   "raw bytes (612)", output: "snapshot retained · processor stopped",
			tool: "normalize/v4", evidence: []string{"E-101", "E-102"},
		},
		{
			id: "CHK-1A7F-A02-S1", attempt: "CHK-1A7F-A02", phase: "ingest",
			title: "接收与指纹", status: "completed",
			start: "2026-11-22T20:40:31+08:00", end: "2026-11-22T20:40:32+08:00",
			summary: "复用不可变原始输入，重新计算内容指纹。",
			input:   "gateway_access_2026-11-22T20-39-58Z.log", output: "sha256:c39f2e0a…b45a",
			tool: "sha256sum", evidence: []string{"E-101"},
		},
		{
			id: "CHK-1A7F-A02-S2", attempt: "CHK-1A7F-A02", phase: "normalize",
			title: "编码与换行规范化", status: "completed",
			start: "2026-11-22T20:40:32+08:00", end: "2026-11-22T20:40:33+08:00",
			summary: "解码 1 个百分号编码 CRLF 序列，原始字节映射已保留。",
			input:   `value="Mozilla/5.0 %0d%0a2026-11-22T20:40:01.000Z INFO audit…"`,
			output:  `value="Mozilla/5.0 \r\n2026-11-22T20:40:01.000Z INFO audit…"`,
			tool:    "normalize/v4", evidence: []string{"E-102"},
		},
		{
			id: "CHK-1A7F-A02-S3", attempt: "CHK-1A7F-A02", phase: "fuzz",
			title: "libFuzzer 语料比对", status: "completed",
			start: "2026-11-22T20:40:33+08:00", end: "2026-11-22T20:40:48+08:00",
			summary: "命中种子 seed_0x4f21；上游采集流断开，未进入关联阶段。",
			input:   "normalized bytes (615)", output: "seed=0x4f21 · 182,204 execs",
			tool: "libFuzzer", evidence: []string{"E-103", "E-105"},
		},
		{
			id: "CHK-1A7F-A02-S4", attempt: "CHK-1A7F-A02", phase: "correlate",
			title: "行边界与来源关联", status: "cancelled",
			start: "2026-11-22T20:40:48+08:00", end: "2026-11-22T20:40:49+08:00",
			summary: "控制台收到上游中断信号，取消本次关联；3 项证据保留。",
			input:   "seed_0x4f21 · line offsets pending", output: "attempt cancelled by upstream",
			tool: "correlate/v2", evidence: []string{"E-101", "E-103", "E-105"},
		},
		{
			id: "CHK-1A7F-A03-S1", attempt: "CHK-1A7F-A03", phase: "ingest",
			title: "接收与指纹", status: "completed",
			start: "2026-11-22T20:41:12+08:00", end: "2026-11-22T20:41:13+08:00",
			summary: "第三次尝试从不可变原始输入重新开始。",
			input:   "immutable snapshot", output: "sha256:c39f2e0a…b45a", tool: "sha256sum",
			evidence: []string{"E-101"},
		},
		{
			id: "CHK-1A7F-A03-S2", attempt: "CHK-1A7F-A03", phase: "normalize",
			title: "编码与换行规范化", status: "completed",
			start: "2026-11-22T20:41:13+08:00", end: "2026-11-22T20:41:14+08:00",
			summary: "规范化成功，生成可逆字节映射。",
			input:   "raw bytes (612)", output: "normalized bytes (615)", tool: "normalize/v4",
			evidence: []string{"E-102"},
		},
		{
			id: "CHK-1A7F-A03-S3", attempt: "CHK-1A7F-A03", phase: "fuzz",
			title: "libFuzzer 语料比对", status: "completed",
			start: "2026-11-22T20:41:14+08:00", end: "2026-11-22T20:41:30+08:00",
			summary: "复现 seed_0x4f21，提取 91 B 最小输入。",
			input:   "seed corpus v6", output: "artifact 91 B · sha256:8b0ce4a9…d91a",
			tool: "libFuzzer", evidence: []string{"E-103", "E-105"},
		},
		{
			id: "CHK-1A7F-A03-S4", attempt: "CHK-1A7F-A03", phase: "seal",
			title: "SQLite 证据写入", status: "failed",
			start: "2026-11-22T20:41:30+08:00", end: "2026-11-22T20:41:31+08:00",
			summary: "写入冲突。已完成的步骤与 3 项证据保持只读，可从此步重试。",
			input:   "3 evidence blobs", output: "SQLITE_BUSY: database is locked",
			tool: "sqlite3", evidence: []string{"E-101", "E-103", "E-105"},
		},
		{
			id: "CHK-1A7F-A04-S1", attempt: "CHK-1A7F-A04", phase: "ingest",
			title: "接收与指纹", status: "completed",
			start: "2026-11-22T20:42:05+08:00", end: "2026-11-22T20:42:05+08:00",
			summary: "锁定原始输入快照；内容哈希与采集端声明一致。",
			input:   "gateway_access_2026-11-22T20-39-58Z.log · 612 B",
			output:  "sha256:c39f2e0a…b45a · immutable=true", tool: "sha256sum",
			evidence: []string{"E-101"},
		},
		{
			id: "CHK-1A7F-A04-S2", attempt: "CHK-1A7F-A04", phase: "normalize",
			title: "编码与换行规范化", status: "completed",
			start: "2026-11-22T20:42:05+08:00", end: "2026-11-22T20:42:06+08:00",
			summary: "解码 1 个百分号编码 CRLF 序列；生成可逆字节偏移表。",
			input:   `%0d%0a → CR LF @ byte 328`, output: "normalized bytes · mapping retained",
			tool: "normalize/v4", evidence: []string{"E-102"},
		},
		{
			id: "CHK-1A7F-A04-S3", attempt: "CHK-1A7F-A04", phase: "fuzz",
			title: "libFuzzer 语料比对", status: "completed",
			start: "2026-11-22T20:42:06+08:00", end: "2026-11-22T20:42:16+08:00",
			summary: "182,204 次执行、0 崩溃；命中并最小化注入种子。",
			input:   "corpus-log-injection-v6 · 148 seeds",
			output:  "seed_0x4f21 → 91 B artifact · 0 crashes", tool: "libFuzzer / LLVM 20.1.8",
			evidence: []string{"E-103", "E-105"},
		},
		{
			id: "CHK-1A7F-A04-S4", attempt: "CHK-1A7F-A04", phase: "correlate",
			title: "行边界与来源关联", status: "completed",
			start: "2026-11-22T20:42:16+08:00", end: "2026-11-22T20:42:17+08:00",
			summary: "确认伪造审计行来自 user-agent；U+2028 边界规则无法判断。",
			input:   "normalized bytes + line map",
			output:  "LOG-014 hit @ line 3 · BOUNDARY-07 indeterminate", tool: "correlate/v2",
			evidence: []string{"E-103", "E-104", "E-105"}, ambiguous: true,
		},
		{
			id: "CHK-1A7F-A04-S5", attempt: "CHK-1A7F-A04", phase: "verdict",
			title: "风险规则判定", status: "completed",
			start: "2026-11-22T20:42:17+08:00", end: "2026-11-22T20:42:17+08:00",
			summary: "综合规则 LOG-014 与 LOG-021，输出高置信自动结论。",
			input:   "2 confirmed findings + 1 boundary",
			output:  "malicious · confidence 0.93", tool: "rules/v18",
			evidence: []string{"E-103", "E-104"},
		},
		{
			id: "CHK-1A7F-A04-S6", attempt: "CHK-1A7F-A04", phase: "seal",
			title: "SQLite 证据封存", status: "completed",
			start: "2026-11-22T20:42:17+08:00", end: "2026-11-22T20:42:18+08:00",
			summary: "5 项证据写入 SQLite（WAL + fsync），来源链闭合。",
			input:   "5 evidence blobs", output: "sealed · integrity=ok · attempt A04",
			tool: "sqlite3", evidence: []string{"E-101", "E-102", "E-103", "E-104", "E-105"},
		},
	}
	positions := make(map[string]int)
	for _, st := range steps {
		ev, _ := json.Marshal(st.evidence)
		var end any
		if st.end != "" {
			end = st.end
		}
		ambiguous := 0
		if st.ambiguous {
			ambiguous = 1
		}
		positions[st.attempt]++
		pos := positions[st.attempt]
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO steps (id, attempt_id, position, phase, title, status, started_at, ended_at,
				summary, input_excerpt, output_excerpt, tool, evidence_ids, ambiguous)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			st.id, st.attempt, pos, st.phase, st.title, st.status, st.start, end,
			st.summary, st.input, st.output, st.tool, string(ev), ambiguous,
		); err != nil {
			return fmt.Errorf("insert step %s: %w", st.id, err)
		}
	}
	return nil
}

func seedEvidence(ctx context.Context, tx *sql.Tx, checkID string) error {
	type evidenceSeed struct {
		id, attempt, step, label, kind, content, created string
		retained                                         bool
	}
	decoded := "field=\"user-agent\" value=\"Mozilla/5.0 \r\n2026-11-22T20:40:01.000Z INFO audit actor=admin action=export status=ok\""
	forged := "2026-11-22T20:40:01.000Z INFO audit actor=admin action=export status=ok"
	boundary := "field=\"x-partner\" value=\"alpha\u2028beta\"\nhex: 61 6c 70 68 61 e2 80 a8 62 65 74 61"
	minimal := "%0d%0a2026-11-22T20:40:01.000Z INFO audit actor=admin action=export status=ok"
	items := []evidenceSeed{
		{id: "E-101", attempt: "CHK-1A7F-A04", step: "CHK-1A7F-A04-S1",
			label: "原始输入快照", kind: "raw", content: sampleLog,
			created: "2026-11-22T20:42:05+08:00", retained: true},
		{id: "E-102", attempt: "CHK-1A7F-A04", step: "CHK-1A7F-A04-S2",
			label: "CRLF 解码映射", kind: "normalized", content: decoded,
			created: "2026-11-22T20:42:06+08:00", retained: true},
		{id: "E-103", attempt: "CHK-1A7F-A04", step: "CHK-1A7F-A04-S4",
			label: "伪造审计行", kind: "derived", content: forged,
			created: "2026-11-22T20:42:16+08:00", retained: true},
		{id: "E-104", attempt: "CHK-1A7F-A04", step: "CHK-1A7F-A04-S4",
			label: "U+2028 边界样本", kind: "boundary", content: boundary,
			created: "2026-11-22T20:42:16+08:00", retained: true},
		{id: "E-105", attempt: "CHK-1A7F-A04", step: "CHK-1A7F-A04-S3",
			label: "libFuzzer 最小复现输入", kind: "fuzzer-artifact", content: minimal,
			created: "2026-11-22T20:42:16+08:00", retained: true},
	}
	for _, e := range items {
		retained := 0
		if e.retained {
			retained = 1
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO evidence (id, check_id, attempt_id, step_id, label, kind, sha256, size,
				content, retained, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.id, checkID, e.attempt, e.step, e.label, e.kind, Hash([]byte(e.content)),
			len([]byte(e.content)), []byte(e.content), retained, e.created,
		); err != nil {
			return fmt.Errorf("insert evidence %s: %w", e.id, err)
		}
	}
	return nil
}

func seedFindings(ctx context.Context, tx *sql.Tx, checkID string) error {
	type findingSeed struct {
		id, rule, title, severity, detail, step, evidence string
		confidence                                        float64
	}
	findings := []findingSeed{
		{
			id: "FND-01", rule: "LOG-014", title: "CRLF 换行注入", severity: "high",
			confidence: 0.98, step: "CHK-1A7F-A04-S4", evidence: "E-103",
			detail: "user-agent 引用字段中的 %0d%0a 被解码为 CR LF，使后续文本成为独立日志行。",
		},
		{
			id: "FND-02", rule: "LOG-021", title: "伪造审计身份", severity: "high",
			confidence: 0.91, step: "CHK-1A7F-A04-S4", evidence: "E-103",
			detail: "注入行伪装为 actor=admin 的导出审计事件，可污染下游审计检索。",
		},
		{
			id: "FND-03", rule: "BOUNDARY-07", title: "U+2028 行分隔符边界", severity: "unknown",
			confidence: 0.50, step: "CHK-1A7F-A04-S4", evidence: "E-104",
			detail: "带引号字段内的 U+2028 是否被上游解析器视为换行，取决于解析器版本，自动规则无法判断。",
		},
	}
	for i, f := range findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO findings (id, check_id, rule, title, severity, confidence, detail,
				step_id, evidence_id, position)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.id, checkID, f.rule, f.title, f.severity, f.confidence, f.detail,
			f.step, f.evidence, i+1,
		); err != nil {
			return fmt.Errorf("insert finding %s: %w", f.id, err)
		}
	}
	return nil
}

func seedAudits(ctx context.Context, tx *sql.Tx, checkID string) error {
	type auditSeed struct {
		id, attempt, event, actor, detail, created string
	}
	audits := []auditSeed{
		{"AUD-01", "", "check.created", "ingest-agent", "从 edge-gateway 接收原始输入，612 B。", "2026-11-22T20:39:58+08:00"},
		{"AUD-02", "CHK-1A7F-A01", "attempt.cancelled", "林澈 · 当班分析员", "中途取消 #1：疑似生产令牌，停止扩散。", "2026-11-22T20:40:18+08:00"},
		{"AUD-03", "CHK-1A7F-A02", "attempt.cancelled", "控制台 · 自动取消", "中途取消 #2：上游采集中断，输入不完整。", "2026-11-22T20:40:49+08:00"},
		{"AUD-04", "CHK-1A7F-A03", "attempt.failed", "sqlite-worker-2", "SQLITE_BUSY；已保留 3 项证据。", "2026-11-22T20:41:31+08:00"},
		{"AUD-05", "CHK-1A7F-A04", "attempt.completed", "detector-worker-1", "5 项证据封存，自动结论已生成。", "2026-11-22T20:42:18+08:00"},
		{"AUD-06", "CHK-1A7F-A04", "boundary.unresolved", "rules/v18", "BOUNDARY-07：U+2028 需人工确认。", "2026-11-22T20:42:17+08:00"},
		{"AUD-07", "", "human.confirmed", "周雪 · 安全运营", "确认日志注入；处置单 SEC-4821。", "2026-11-22T21:08:42+08:00"},
	}
	for _, a := range audits {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audits (id, check_id, attempt_id, event, actor, detail, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			a.id, checkID, a.attempt, a.event, a.actor, a.detail, a.created,
		); err != nil {
			return fmt.Errorf("insert audit %s: %w", a.id, err)
		}
	}
	return nil
}

func mustTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return t
}

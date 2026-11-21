package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

func seedFindings(ctx context.Context, tx *sql.Tx, extData []byte) error {
	conclusions := []Conclusion{
		{
			ID: "AC-01", Origin: "automatic", Category: "replay",
			Title:  "恢复后重放稳定复现",
			Detail: "R-002 从 job-7fe2 恢复后连续重放 3 次，3/3 命中同一崩溃指纹 9e1c4bd2。",
			Status: "confirmed", Confidence: 1.0, Severity: "high",
			RuleID: "REPLAY-3OF3", StepID: "S-005",
			EvidenceIDs: []string{"E-004", "E-005", "E-009"},
			InputRef:    "recovered_0x7e.kz3#0x00-0x54", Boundary: -1,
			ManualCheckID: "MC-01",
		},
		{
			ID: "AC-02", Origin: "automatic", Category: "crash",
			Title:  "ASan 命中 RZ31 记录越界读",
			Detail: "heap-buffer-overflow，READ size 1，位置在 kz3/record.c:88；读取发生在 84 B 输入末尾之后。",
			Status: "confirmed", Confidence: 0.98, Severity: "critical",
			RuleID: "ASAN-STACK", StepID: "S-005",
			EvidenceIDs: []string{"E-005", "E-009"},
			InputRef:    "recovered_0x7e.kz3#0x29-0x54", Boundary: 41,
			ManualCheckID: "MC-02",
		},
		{
			ID: "AC-03", Origin: "automatic", Category: "provenance",
			Title:  "来源链完整且哈希一致",
			Detail: "原始 84 B → 接收封存 → libFuzzer 重放 → ASan 输出 → SQLite 快照；每跳均有独立 SHA-256。",
			Status: "confirmed", Confidence: 1.0, Severity: "info",
			RuleID: "ORIGIN-SHA256", StepID: "S-007",
			EvidenceIDs: []string{"E-001", "E-002", "E-005", "E-008"},
			InputRef:    "recovered_0x7e.kz3#0x00-0x54", Boundary: -1,
			ManualCheckID: "MC-03",
		},
		{
			ID: "AC-04", Origin: "automatic", Category: "extension",
			Title:  "未知扩展 0x7E 的语义无法判断",
			Detail: "注册表无 0x7E；12 B 扩展块后紧接 43 B payload。字节不足以区分包装层字段和业务层数据。",
			Status: "undecided", Confidence: 0.41, Severity: "medium",
			RuleID: "EXT-UNKNOWN", StepID: "S-006",
			EvidenceIDs: []string{"E-006", "E-007", "E-009"},
			InputRef:    "recovered_0x7e.kz3#0x14-0x29", Boundary: 41,
			Undecidable:   "扩展注册表没有 0x7E；0x29 是记录边界，但其后字节属于包装层还是业务层没有规范证据。",
			ManualCheckID: "MC-04",
		},
		{
			ID: "AC-05", Origin: "automatic", Category: "recovery",
			Title:  "首次失败，恢复后可重放",
			Detail: "R-001 因符号化通道不可达失败；job-7fe2 从 journal 恢复后 R-002 成功，失败输出未混入结论。",
			Status: "confirmed", Confidence: 0.99, Severity: "info",
			RuleID: "RECOVERY-JOURNAL", StepID: "S-004",
			EvidenceIDs: []string{"E-003", "E-004", "E-005"},
			InputRef:    "recovered_0x7e.kz3#0x00-0x54", Boundary: -1,
			ManualCheckID: "",
		},
	}
	for _, c := range conclusions {
		evidenceJSON, err := json.Marshal(c.EvidenceIDs)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO conclusions
			(id, sample_id, origin, category, title, detail, status, confidence,
			 severity, rule_id, step_id, evidence_ids, input_ref, boundary,
			 undecidable_reason, manual_check_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, seedSampleID, c.Origin, c.Category, c.Title, c.Detail,
			c.Status, c.Confidence, c.Severity, c.RuleID, c.StepID,
			string(evidenceJSON), c.InputRef, c.Boundary, c.Undecidable, c.ManualCheckID)
		if err != nil {
			return fmt.Errorf("insert conclusion %s: %w", c.ID, err)
		}
	}

	checks := []ManualCheck{
		{
			ID: "MC-01", ConclusionID: "AC-01",
			Question: "3/3 重放是否足以排除环境偶发？",
			Guidance: "比对 R-001/R-002 的输入哈希、fuzzer 二进制哈希和 worker fingerprint；确认一致后签署。",
		},
		{
			ID: "MC-02", ConclusionID: "AC-02",
			Question: "是否确认根因归属 kz3_record_next / record.c:88？",
			Guidance: "核对 ASan 栈的构建 SHA、源码行号与最小样本；确认栈未被恢复过程改写。",
		},
		{
			ID: "MC-03", ConclusionID: "AC-03",
			Question: "是否接受当前来源链作为审计基线？",
			Guidance: "检查原始样本、replay 日志、manifest 三者的 SHA-256 是否与 SQLite 快照一致。",
		},
		{
			ID: "MC-04", ConclusionID: "AC-04",
			Question: "0x7E 扩展块应作为包装层忽略，还是业务 payload？",
			Guidance: "需要 kz3 容器 owner 提供扩展注册表或协议规范；在此之前不得自动归属组件。",
		},
	}
	for _, check := range checks {
		_, err := tx.ExecContext(ctx, `INSERT INTO manual_checks
			(id, sample_id, conclusion_id, question, guidance, status,
			 reviewer, note, updated_at)
			VALUES (?, ?, ?, ?, ?, 'pending', '', '', ?)`,
			check.ID, seedSampleID, check.ConclusionID, check.Question,
			check.Guidance, "2026-11-19T08:46:38Z")
		if err != nil {
			return fmt.Errorf("insert manual check %s: %w", check.ID, err)
		}
	}
	return nil
}

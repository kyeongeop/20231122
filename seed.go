package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
)

const (
	rawInput       = "/srv/www/uploads/%2e%2e/%2E%2E/etc/passwd.unk9"
	decodedInput   = "/srv/www/uploads/../../etc/passwd.unk9"
	legacyOutput   = "/srv/etc/passwd.unk9"
	hardenedOutput = "/srv/www/etc/passwd.unk9"
)

type seededEvidence struct {
	id, label, kind, content, mediaType, capturedAt, origin string
}

func (s *Store) seed() error {
	exists, err := s.caseExists()
	if err != nil || exists {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
INSERT INTO cases (id, title, status, severity, summary, target, toolchain, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.caseID,
		"路径规范化差异",
		"needs_review",
		"high",
		"恢复后的语料重放出现根路径分歧；未知扩展 `.unk9` 触发兼容回退。符号链接快照缺失，根边界暂不可判定。",
		"pathnorm_fuzz.c:87 · resolve_boundary()",
		"Go 1.27.4 · libFuzzer 17.0.6 · SQLite 3.46.1 / WAL",
		"2026-11-22T23:51:06+08:00",
		"2026-11-23T00:41:22+08:00",
	); err != nil {
		return fmt.Errorf("seed case: %w", err)
	}

	evidence := []seededEvidence{
		{"EV-RAW", "libFuzzer 原始语料", "corpus", rawInput, "application/octet-stream",
			"2026-11-22T23:51:06+08:00", "artifacts/corpus/recovered/minimized-01"},
		{"EV-DECODE", "单次解码结果", "derived", decodedInput, "text/plain",
			"2026-11-23T00:08:47+08:00", "replay:decode@S-03"},
		{"EV-LEGACY", "legacy.Resolve 输出", "output", legacyOutput, "text/plain",
			"2026-11-23T00:08:47+08:00", "replay:legacy@S-04"},
		{"EV-HARDENED", "hardened.Resolve 输出", "output", hardenedOutput, "text/plain",
			"2026-11-23T00:08:47+08:00", "replay:hardened@S-05"},
		{"EV-FAIL", "首次恢复重放 stderr", "log", "corpus checksum mismatch: expected 4c9a0e2b, got 00000000\nsqlite recovery point: wal frame 1841\nreplay refused; partial output discarded\n", "text/plain",
			"2026-11-23T00:06:12+08:00", "artifacts/replays/attempt-01.stderr"},
	}
	for _, ev := range evidence {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(ev.content)))
		if _, err := tx.Exec(`
INSERT INTO evidence (id, case_id, label, kind, sha256, size, media_type, content, captured_at, origin, immutable)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
			ev.id, s.caseID, ev.label, ev.kind, hash, len([]byte(ev.content)),
			ev.mediaType, ev.content, ev.capturedAt, ev.origin,
		); err != nil {
			return fmt.Errorf("seed evidence %s: %w", ev.id, err)
		}
	}

	steps := []Step{
		{"S-00", s.caseID, 0, "corpus", "libFuzzer 捕获原始输入",
			"最小化语料由 pathnorm_fuzz 的扩展分派分支生成，原始字节未做转义。",
			"captured", "2026-11-22T23:51:06+08:00", "EV-RAW",
			"./pathnorm_fuzz -runs=1 artifacts/corpus/recovered/minimized-01",
			"artifact: minimized-01 · 46 bytes · new coverage: 18 edges",
			[]string{"EV-RAW", "AUTO-01"}},
		{"S-01", s.caseID, 1, "recovery", "恢复后首次重放失败",
			"SQLite WAL 恢复后语料索引指向旧帧，校验和不一致，重放被拒绝；未保留部分输出。",
			"failed", "2026-11-23T00:06:12+08:00", "EV-FAIL",
			"./pathnorm_fuzz -runs=1 artifacts/corpus/recovered/minimized-01",
			"exit 2 · corpus checksum mismatch · partial output discarded",
			[]string{"EV-FAIL", "FU-01"}},
		{"S-02", s.caseID, 2, "replay", "恢复后重放成功",
			"按处置单重算语料摘要并重新挂载恢复点后重放；输入 SHA-256 与原始语料一致。",
			"success", "2026-11-23T00:08:47+08:00", "EV-RAW",
			"./pathnorm_fuzz -runs=1 -artifact_prefix=artifacts/replays/ artifacts/corpus/recovered/minimized-01",
			"Executed minimized-01 in 41 ms · 1 input · SHA-256 matched",
			[]string{"REPLAY-02", "EV-RAW"}},
		{"S-03", s.caseID, 3, "decode", "单次百分号解码",
			"仅执行一次百分号解码，不折叠分隔符。`%2e%2e` 与 `%2E%2E` 均变为 `..`。",
			"success", "2026-11-23T00:08:47+08:00", "EV-DECODE",
			"replay.decode(raw, {percentOnce: true, separatorFold: false})",
			decodedInput,
			[]string{"EV-DECODE", "AUTO-01"}},
		{"S-04", s.caseID, 4, "normalize", "legacy.Resolve 词法归一化",
			"旧实现先处理 `.` 与 `..` 再拼接根目录，父级段越过 `/srv/www` 后生成 `/srv/etc`。",
			"warning", "2026-11-23T00:08:47+08:00", "EV-LEGACY",
			"legacy.Resolve(decoded, root=\"/srv/www\")",
			legacyOutput,
			[]string{"EV-LEGACY", "AUTO-01"}},
		{"S-05", s.caseID, 5, "normalize", "hardened.Resolve 根界归一化",
			"新实现将父级段钳制在挂载根内，输出仍位于 `/srv/www`。",
			"success", "2026-11-23T00:08:47+08:00", "EV-HARDENED",
			"hardened.Resolve(decoded, root=\"/srv/www\")",
			hardenedOutput,
			[]string{"EV-HARDENED", "AUTO-01"}},
		{"S-06", s.caseID, 6, "extension", "未知扩展命中兼容回退",
			"`.unk9` 不在扩展注册表中，分派器回退到 legacy.Resolve；回退路径没有根界校验。",
			"warning", "2026-11-23T00:08:47+08:00", "EV-RAW",
			"gate.Extension(\".unk9\") → FALLBACK_LEGACY",
			"extension=.unk9 · registered=false · resolver=legacy.Resolve",
			[]string{"AUTO-02", "EV-RAW"}},
		{"S-07", s.caseID, 7, "boundary", "根边界判定",
			"`/srv/www/uploads` 在运行时的符号链接目标未采集；无法区分词法越界与重基线后的安全输出。",
			"undecidable", "2026-11-23T00:41:22+08:00", "EV-RAW",
			"stat /srv/www/uploads",
			"symbolic-link snapshot: MISSING · hypothesis H1/H2 both consistent with captured bytes",
			[]string{"U-03", "FU-02", "EV-RAW"}},
	}
	for _, step := range steps {
		if _, err := tx.Exec(`
INSERT INTO steps (id, case_id, sequence, kind, title, detail, status, occurred_at, evidence_id, command, output, refs_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			step.ID, step.CaseID, step.Sequence, step.Kind, step.Title, step.Detail,
			step.Status, step.OccurredAt, step.EvidenceID, step.Command, step.Output,
			encodeStrings(step.Refs),
		); err != nil {
			return fmt.Errorf("seed step %s: %w", step.ID, err)
		}
	}

	if err := seedFindings(tx, s.caseID); err != nil {
		return err
	}
	if err := seedFollowups(tx, s.caseID); err != nil {
		return err
	}
	if err := seedReplays(tx, s.caseID); err != nil {
		return err
	}
	return tx.Commit()
}

func evidenceSHA(content string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(content))))
}

func seedFindings(tx *sql.Tx, caseID string) error {
	findings := []Finding{
		{"AUTO-01", caseID, "双后端产生不同根路径", "同一解码输入分别进入 legacy 与 hardened；在 `/srv/www` 根界处出现路径前缀分歧，差异可稳定复现。", "high", 96, "reproducible", []string{"S-03", "S-04", "S-05", "EV-LEGACY", "EV-HARDENED"}, "2026-11-23T00:08:48+08:00"},
		{"AUTO-02", caseID, "未知扩展触发兼容回退", "`.unk9` 未登记，扩展分派器回退至 legacy.Resolve；该分支不执行 hardened 的根界钳制。", "medium", 84, "reproducible", []string{"S-06", "EV-RAW"}, "2026-11-23T00:08:48+08:00"},
	}
	for _, f := range findings {
		if _, err := tx.Exec(`
INSERT INTO findings (id, case_id, title, detail, severity, confidence, disposition, refs_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, f.CaseID, f.Title, f.Detail, f.Severity, f.Confidence,
			f.Disposition, encodeStrings(f.Refs), f.CreatedAt,
		); err != nil {
			return fmt.Errorf("seed finding %s: %w", f.ID, err)
		}
	}
	return nil
}

func seedFollowups(tx *sql.Tx, caseID string) error {
	followups := []Followup{
		{"FU-01", caseID, "修复恢复重放失败", "首次重放因语料摘要与 SQLite 恢复帧不一致退出。先校验数据库，再重算语料摘要并重新重放。", []string{
			`sqlite3 data/pathscope.db "PRAGMA integrity_check;"`,
			`sha256sum artifacts/corpus/recovered/minimized-01`,
			`./pathnorm_fuzz -runs=1 artifacts/corpus/recovered/minimized-01`,
		}, "resolved", "replay-worker", "2026-11-23T00:06:14+08:00"},
		{"FU-02", caseID, "采集根边界符号链接快照", "补采挂载点的解析目标与文件系统信息，才能判断 `/srv/etc` 是否实际越出预期根。", []string{
			`stat -c '%N' /srv/www/uploads`,
			`readlink -f /srv/www/uploads`,
			`findmnt -T /srv/www/uploads -o TARGET,SOURCE,FSTYPE`,
		}, "open", "unassigned", "2026-11-23T00:41:22+08:00"},
	}
	for _, f := range followups {
		if _, err := tx.Exec(`
INSERT INTO followups (id, case_id, title, reason, commands_json, status, owner, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, f.CaseID, f.Title, f.Reason, encodeStrings(f.Commands),
			f.Status, f.Owner, f.CreatedAt,
		); err != nil {
			return fmt.Errorf("seed followup %s: %w", f.ID, err)
		}
	}
	return nil
}

func seedReplays(tx *sql.Tx, caseID string) error {
	replays := []Replay{
		{"REPLAY-01", caseID, 1, "failed", "./pathnorm_fuzz -runs=1 artifacts/corpus/recovered/minimized-01",
			"2026-11-23T00:06:11+08:00", "2026-11-23T00:06:12+08:00", 2, "",
			"corpus checksum mismatch: expected 4c9a0e2b, got 00000000"},
		{"REPLAY-02", caseID, 2, "succeeded", "./pathnorm_fuzz -runs=1 -artifact_prefix=artifacts/replays/ artifacts/corpus/recovered/minimized-01",
			"2026-11-23T00:08:46+08:00", "2026-11-23T00:08:47+08:00", 0,
			"INFO: Running with entropic power schedule (30, 100).\nExecuted minimized-01 in 41 ms\nSHA-256 matched: " + evidenceSHA(rawInput),
			""},
	}
	for _, r := range replays {
		if _, err := tx.Exec(`
INSERT INTO replays (id, case_id, attempt, status, command, started_at, finished_at, exit_code, stdout, stderr)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.CaseID, r.Attempt, r.Status, r.Command, r.StartedAt, r.FinishedAt,
			r.ExitCode, r.Stdout, r.Stderr,
		); err != nil {
			return fmt.Errorf("seed replay %s: %w", r.ID, err)
		}
	}
	return nil
}

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crashprovenance/internal/forensics"
)

const seedSampleID = "C-8842"

func (s *Store) seed(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM samples").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	original := forensics.BuildSeedSample()
	digest := forensics.Digest(original)
	received := "2026-11-19T08:39:12Z"
	sample := Sample{
		ID:          seedSampleID,
		CaseNo:      "INC-2026-1119-047",
		Incident:    "Waypoint 网关进程崩溃",
		Filename:    forensics.SampleName,
		Extension:   forensics.Extension,
		Size:        len(original),
		SHA256:      digest,
		Status:      "needs_review",
		Severity:    "high",
		Summary:     "恢复后重放 3/3 复现。自动归因在 0x7E 未知扩展边界停止，等待人工确认。",
		Owner:       "Waypoint Runtime / kz3 parser",
		ReceivedAt:  received,
		RecoveredAt: "2026-11-19T08:44:02Z",
		FrozenAt:    "2026-11-19T08:46:38Z",
		StoragePath: "evidence/samples/recovered_0x7e.kz3",
	}
	if err := insertSample(ctx, tx, sample, original); err != nil {
		return err
	}

	steps := []Step{
		{ID: "S-001", Seq: 1, Phase: "intake", Title: "接收并封存原始样本", Status: "passed",
			StartedAt: received, FinishedAt: "2026-11-19T08:39:19Z",
			Command: "sha256sum evidence/samples/recovered_0x7e.kz3",
			Detail:  "84 B 输入按原始字节写入只读对象；文件名、扩展名、SHA-256 同时登记。", Hash: digest},
		{ID: "S-002", Seq: 2, Phase: "fuzz", Title: "libFuzzer 复现并最小化", Status: "passed",
			StartedAt: "2026-11-19T08:40:03Z", FinishedAt: "2026-11-19T08:41:02Z",
			Command: "./fuzz/kz3_fuzz -runs=200000 seed_corpus/",
			Detail:  "命中 RZ31 record 边界；保留 84 B 最小输入和原始语料路径。", Hash: "crash:9e1c4bd2"},
		{ID: "S-003", Seq: 3, Phase: "replay", Title: "第 1 次恢复后重放", Status: "failed",
			StartedAt: "2026-11-19T08:42:10Z", FinishedAt: "2026-11-19T08:42:11Z",
			Command: "./fuzz/replay evidence/samples/recovered_0x7e.kz3",
			Detail:  "符号化通道不可达，未产出可校验栈；输入和工作目录保持不变，未生成归因结论。"},
		{ID: "S-004", Seq: 4, Phase: "recovery", Title: "从 job journal 恢复 worker", Status: "passed",
			StartedAt: "2026-11-19T08:44:02Z", FinishedAt: "2026-11-19T08:44:09Z",
			Command: "systemctl start crash-worker && journal-recover job-7fe2",
			Detail:  "恢复 job-7fe2；输入哈希、工作目录 fingerprint、fuzzer 二进制哈希三项一致。", Hash: digest},
		{ID: "S-005", Seq: 5, Phase: "replay", Title: "第 2 次恢复后重放", Status: "passed",
			StartedAt: "2026-11-19T08:44:31Z", FinishedAt: "2026-11-19T08:44:39Z",
			Command: "./fuzz/replay evidence/samples/recovered_0x7e.kz3 -runs=3",
			Detail:  "3/3 复现；ASan 指纹一致；重放输出与原始输入哈希共同封存。", Hash: "crash:9e1c4bd2"},
		{ID: "S-006", Seq: 6, Phase: "attribution", Title: "自动归因与边界判定", Status: "warning",
			StartedAt: "2026-11-19T08:45:03Z", FinishedAt: "2026-11-19T08:45:12Z",
			Command: "go run ./cmd/attrib -sample C-8842",
			Detail:  "5 条自动结论成立；0x7E 扩展语义超过可判边界，规则 EXT-UNKNOWN 返回 undecidable。",
			Hash:    "trace:7a61f0c9"},
		{ID: "S-007", Seq: 7, Phase: "seal", Title: "证据链封存", Status: "passed",
			StartedAt: "2026-11-19T08:46:38Z", FinishedAt: "2026-11-19T08:46:38Z",
			Command: "sqlite3 evidence/forensics.db '.backup evidence/snapshots/C-8842.db'",
			Detail:  "SQLite 快照、对象摘要与 SHA-256 清单一并冻结；后续状态变更只追加。",
			Hash:    "snapshot:C-8842@2026-11-19T08:46:38Z"},
	}
	for _, step := range steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO steps
			(id, sample_id, seq, phase, title, status, started_at, finished_at, command, detail, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			step.ID, seedSampleID, step.Seq, step.Phase, step.Title, step.Status,
			step.StartedAt, step.FinishedAt, step.Command, step.Detail, step.Hash); err != nil {
			return fmt.Errorf("insert step %s: %w", step.ID, err)
		}
	}

	extData := original[forensics.UnknownDataOff:41]
	if err := seedEvidence(ctx, s, tx, sample, extData); err != nil {
		return err
	}
	if err := seedFindings(ctx, tx, extData); err != nil {
		return err
	}
	if err := writeSeedObject(s.baseDir, sample.StoragePath, original); err != nil {
		return err
	}
	return tx.Commit()
}

func insertSample(ctx context.Context, tx *sql.Tx, sample Sample, original []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO samples
		(id, case_no, incident, filename, extension, size, sha256, original, status,
		 severity, summary, owner, received_at, recovered_at, frozen_at, storage_path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.ID, sample.CaseNo, sample.Incident, sample.Filename, sample.Extension,
		sample.Size, sample.SHA256, original, sample.Status, sample.Severity,
		sample.Summary, sample.Owner, sample.ReceivedAt, sample.RecoveredAt,
		sample.FrozenAt, sample.StoragePath)
	if err != nil {
		return fmt.Errorf("insert sample: %w", err)
	}
	return nil
}

func contentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func objectPath(baseDir, digest, suffix string) string {
	name := digest
	if suffix != "" {
		name += suffix
	}
	return filepath.Join(baseDir, "objects", name)
}

func writeSeedObject(baseDir, rel string, content []byte) error {
	path := filepath.Join(baseDir, filepath.Base(rel))
	if strings.HasPrefix(rel, "evidence/samples/") {
		path = filepath.Join(baseDir, "samples", filepath.Base(rel))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o444)
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

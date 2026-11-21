package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"crashprovenance/internal/forensics"
)

func (s *Store) addEvidence(ctx context.Context, tx *sql.Tx, id, stepID, kind, label, mime string, content []byte, createdAt string) error {
	digest := contentDigest(content)
	ext := ""
	switch {
	case strings.Contains(mime, "json"):
		ext = ".json"
	case strings.Contains(mime, "text"):
		ext = ".log"
	case kind == "original" || kind == "bytes":
		ext = ".bin"
	}
	path := objectPath(s.baseDir, digest, ext)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o444); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO evidence
		(id, sample_id, step_id, kind, label, mime, sha256, size, created_at, path, content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, seedSampleID, stepID, kind, label, mime, digest, len(content),
		createdAt, path, content)
	if err != nil {
		return fmt.Errorf("insert evidence %s: %w", id, err)
	}
	return nil
}

func seedEvidence(ctx context.Context, s *Store, tx *sql.Tx, sample Sample, extData []byte) error {
	sampleSHA := sample.SHA256
	extSHA := contentDigest(extData)

	fuzzSummary := fmt.Sprintf(`libFuzzer replay summary
case: %s
campaign: kz3-record-boundary
runs: 200000
artifact: %s
sha256: %s
minimized_bytes: 84
crash: heap-buffer-overflow
crash_fingerprint: 9e1c4bd2
`, sample.CaseNo, sample.Filename, sampleSHA)
	failedReplay := fmt.Sprintf(`2026-11-19T08:42:10Z replay attempt=1
input=%s
sha256=%s
symbolizer=tcp://127.0.0.1:9401
error="connection refused"
result=NO_SYMBOLIZED_STACK
worker_state=quarantined
next_action=restore job-7fe2 from journal, verify input hash, retry with local symbolizer
`, sample.Filename, sampleSHA)
	journal := fmt.Sprintf(`{
  "job_id": "job-7fe2",
  "state": "recovered",
  "sample_id": "%s",
  "input_sha256": "%s",
  "workdir_fingerprint": "wb-7d4c9a11",
  "fuzzer_binary_sha256": "b91dab0c6d7f2c4d",
  "recovered_at": "2026-11-19T08:44:02Z",
  "checks": ["input_hash", "workdir", "fuzzer_binary"]
}
`, sample.ID, sampleSHA)
	replayLog := fmt.Sprintf(`replay suite: %s
input_sha256: %s
attempts: 3
reproduced: 3
result: CRASH_REPRODUCED
exit_code: 77
asan_fingerprint: 9e1c4bd2
article_path: evidence/objects/%s
`, sample.CaseNo, sampleSHA, sampleSHA)
	asanLog := fmt.Sprintf(`==18842==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000ff
READ of size 1 at 0x6020000000ff thread T0
    #0 0x55c8b6a31e9c in kz3_record_next /src/kz3/record.c:88:18
    #1 0x55c8b6a30f41 in kz3_parse /src/kz3/parser.c:141:12
    #2 0x55c8b6a30788 in LLVMFuzzerTestOneInput /src/fuzz/kz3_fuzz.c:61:10
    #3 0x55c8b6a3f72d in fuzzer::Fuzzer::ExecuteCallback
    #4 0x55c8b6a40c90 in fuzzer::Fuzzer::RunOne
    #5 0x55c8b6a3aadb in main

0x6020000000ff is located 0 bytes after 84-byte region [0x6020000000a0,0x6020000000f4)
allocated by thread T0 here:
    #0 0x55c8b6a5c3a8 in operator new[](unsigned long)
    #1 0x55c8b6a30710 in LLVMFuzzerTestOneInput /src/fuzz/kz3_fuzz.c:31:19

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/kz3/record.c:88:18 in kz3_record_next
input_sha256: %s
unknown_extension: 0x7e
boundary_offset: 0x29
`, sampleSHA)
	trace := fmt.Sprintf(`{
  "case": "%s",
  "input_sha256": "%s",
  "steps": ["S-001", "S-002", "S-003", "S-004", "S-005", "S-006", "S-007"],
  "evidence": ["E-001", "E-002", "E-003", "E-004", "E-005", "E-006", "E-009"],
  "registry_hit": false,
  "unknown_extension": "0x7e",
  "boundary": "0x29",
  "decision": "UNDECIDABLE_BEFORE_SEMANTIC_ATTRIBUTION",
  "reason": "扩展注册表无 0x7e；无法仅从字节判断它是包装层还是业务层。"
}
`, sample.CaseNo, sampleSHA)
	manifest := fmt.Sprintf(`C-8842 evidence manifest
original %s  %s
unknown-extension-0x7e %s  %s
worker-journal recovered_at=2026-11-19T08:44:02Z  job=job-7fe2
replay result=CRASH_REPRODUCED reproduced=3/3 fingerprint=9e1c4bd2
asan rule=heap-buffer-overflow location=record.c:88
sealed_at 2026-11-19T08:46:38Z
`, sampleSHA, sample.Filename, extSHA, "12-byte extension payload")

	items := []struct {
		id, step, kind, label, mime, at string
		content                         []byte
	}{
		{"E-001", "S-001", "original", "原始样本 recovered_0x7e.kz3", "application/octet-stream", sample.ReceivedAt, forensics.BuildSeedSample()},
		{"E-002", "S-002", "fuzzer", "libFuzzer 复现摘要", "text/plain", "2026-11-19T08:41:02Z", []byte(fuzzSummary)},
		{"E-003", "S-003", "log", "首次重放失败日志", "text/plain", "2026-11-19T08:42:11Z", []byte(failedReplay)},
		{"E-004", "S-004", "journal", "worker 恢复 journal", "application/json", "2026-11-19T08:44:09Z", []byte(journal)},
		{"E-005", "S-005", "log", "恢复后重放日志（3/3）", "text/plain", "2026-11-19T08:44:39Z", []byte(replayLog)},
		{"E-006", "S-006", "bytes", "未知扩展 0x7E 原始 12 字节", "application/octet-stream", "2026-11-19T08:45:12Z", extData},
		{"E-007", "S-006", "trace", "自动归因 trace", "application/json", "2026-11-19T08:45:12Z", []byte(trace)},
		{"E-008", "S-007", "manifest", "证据 SHA-256 清单", "text/plain", "2026-11-19T08:46:38Z", []byte(manifest)},
		{"E-009", "S-005", "asan", "ASan 崩溃栈（已符号化）", "text/plain", "2026-11-19T08:44:39Z", []byte(asanLog)},
	}
	for _, item := range items {
		if err := s.addEvidence(ctx, tx, item.id, item.step, item.kind, item.label, item.mime, item.content, item.at); err != nil {
			return err
		}
	}

	_, err := tx.ExecContext(ctx, `INSERT INTO replay_runs
		(id, sample_id, attempt, started_at, finished_at, status, exit_code,
		 reproduced, total, crash_hash, note, evidence_id, recovered_from_job)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"R-001", seedSampleID, 1, "2026-11-19T08:42:10Z", "2026-11-19T08:42:11Z",
		"failed", 1, 0, 3, "", "符号化通道不可达；没有把未校验输出写入结论。", "E-003", "")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO replay_runs
		(id, sample_id, attempt, started_at, finished_at, status, exit_code,
		 reproduced, total, crash_hash, note, evidence_id, recovered_from_job)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"R-002", seedSampleID, 2, "2026-11-19T08:44:31Z", "2026-11-19T08:44:39Z",
		"reproduced", 77, 3, 3, "9e1c4bd2", "从 job-7fe2 恢复后重放；崩溃指纹一致。", "E-005", "job-7fe2")
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO unknown_extensions
		(id, sample_id, tag, offset, length, data_offset, boundary,
		 registry_status, parser_action, raw_hex, evidence_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"U-001", seedSampleID, "0x7E", forensics.UnknownTagOff, len(extData),
		forensics.UnknownDataOff, 41, "unregistered",
		"stop_before_semantic_attribution", forensics.Hex(extData), "E-006")
	return err
}

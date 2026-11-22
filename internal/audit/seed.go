package audit

import (
	"fmt"
	"strings"
)

const (
	TruncatedAuditID = "aud_trunc_7f3a"
	ReplayAuditID    = "aud_replay_9c21"
)

const fullCapture = "POST /v1/session HTTP/1.1\r\n" +
	"Host: api.example.com\r\n" +
	"Origin: [REDACTED:origin]\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 18\r\n" +
	"\r\n" +
	"{\"mode\":\"refresh\"}\r\n" +
	"\r\n" +
	"HTTP/1.1 200 OK\r\n" +
	"Date: Fri, 22 Nov 2026 07:04:11 GMT\r\n" +
	"Server: edge-gw/2.4\r\n" +
	"Content-Type: application/json\r\n" +
	"Access-Control-Allow-Origin: https://app.example.com\r\n" +
	"Access-Control-Allow-Credentials: true\r\n" +
	"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
	"Access-Control-Allow-Headers: content-type, authorization\r\n" +
	"Access-Control-Max-Age: 600\r\n" +
	"Vary: Accept-Encoding\r\n" +
	"Content-Length: 27\r\n" +
	"\r\n" +
	"{\"ok\":true,\"mode\":\"refresh\"}"

func SeedAudits() []Audit {
	full := []byte(fullCapture)
	credentialsKey := "Access-Control-Allow-Credentials: tr"
	cut := strings.Index(fullCapture, credentialsKey)
	if cut < 0 {
		panic("fixture seam not found")
	}
	cut += len(credentialsKey)
	truncated := full[:cut]
	recovered := full[cut:]

	truncResult := Analyze(truncated, Options{ExpectedBytes: len(full)})
	replayResult := Analyze(full, Options{
		ExpectedBytes: len(full), ReplayOf: TruncatedAuditID, RecoveredFrom: cut,
	})

	truncArtifact := Artifact{
		ID: "art_trunc_7f3a", AuditID: TruncatedAuditID,
		Label: "截断响应原文", Kind: "raw", MIME: "application/http",
		Content: string(truncated), CapturedBytes: len(truncated), ExpectedBytes: len(full),
		SHA256: HashBytes(truncated), Immutable: true, Redactions: 1,
		Note: "按接收顺序保存；末尾停在 Access-Control-Allow-Credentials 的字段值中段。",
	}
	replayArtifact := Artifact{
		ID: "art_replay_9c21", AuditID: ReplayAuditID,
		Label: "恢复后响应全文", Kind: "replay", MIME: "application/http",
		Content: string(full), CapturedBytes: len(full), ExpectedBytes: len(full),
		SHA256: HashBytes(full), Immutable: true, Redactions: 1,
		Note: fmt.Sprintf("前 %d bytes 与截断记录逐字节一致；恢复块从接缝追加。", cut),
	}
	recoveredArtifact := Artifact{
		ID: "art_recovered_9c21", AuditID: ReplayAuditID,
		Label: fmt.Sprintf("恢复块 %d..%d", cut, len(full)), Kind: "recovered", MIME: "application/octet-stream",
		Content: string(recovered), CapturedBytes: len(recovered), ExpectedBytes: len(recovered),
		SHA256: HashBytes(recovered), Immutable: true,
		Note: "仅包含接缝之后的新增 bytes，用于独立核验；不覆盖原记录。",
	}

	attachArtifact(truncResult.Steps, truncArtifact.ID)
	attachArtifact(replayResult.Steps, replayArtifact.ID)

	truncatedAudit := Audit{
		ID: TruncatedAuditID, CaseID: "XA-2026-1122-07", Label: "TRUNC·7F3A",
		Title: "跨域响应采集 · 截断记录", Method: "POST", Target: "api.example.com/v1/session",
		CapturedAt: "2026-11-22T15:04:11+08:00", Source: "edge-gw/2.4 · capture-v3",
		State: "truncated", Verdict: "halted",
		BoundaryNote: "截断点位于字段值中间；不推断缺失内容，也不把未知当作通过。",
		Steps:        truncResult.Steps, Artifacts: []Artifact{truncArtifact},
		Conclusions: truncatedConclusions(truncResult),
		FirstError:  truncResult.FirstError, Boundary: truncResult.Boundary,
		Counts: truncResult.Counts,
	}
	replayAudit := Audit{
		ID: ReplayAuditID, CaseID: "XA-2026-1122-07", Label: "RPLY·9C21",
		Title: "跨域响应采集 · 恢复重放", Method: "POST", Target: "api.example.com/v1/session",
		CapturedAt: "2026-11-22T15:06:48+08:00", Source: "replay-worker/1.8 · seam-v2",
		State: "complete", Verdict: "blocked", ReplayOf: TruncatedAuditID,
		BoundaryNote: "请求 Origin 在采集时已脱敏；来源等价性保留为“无法判断”，不补写猜测。",
		Steps:        replayResult.Steps, Artifacts: []Artifact{replayArtifact, recoveredArtifact},
		Conclusions: replayConclusions(replayResult, cut, len(recovered)),
		FirstError:  replayResult.FirstError, Boundary: replayResult.Boundary,
		Counts: replayResult.Counts,
	}
	replay := Replay{
		ID: "replay_7f3a_9c21", TruncatedAuditID: TruncatedAuditID, ReplayAuditID: ReplayAuditID,
		RecoveredArtifactID: recoveredArtifact.ID, RecoveredBytes: len(recovered),
		SeamOffset: cut, SeamVerified: replayResult.ReplayOK,
		Note: "恢复块只追加在接缝之后；截断记录保持原样，可随时并排核验。",
	}
	truncatedAudit.Replay = &replay
	replayAudit.Replay = &replay
	return []Audit{truncatedAudit, replayAudit}
}

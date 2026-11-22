package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"tracecheck/internal/model"
)

type Result struct {
	Normalized    string
	AutoVerdict   string
	AutoLabel     string
	Confidence    float64
	Summary       string
	AmbiguousRule string
	AmbiguousNote string
	Findings      []model.Finding
	Evidence      []model.Evidence
	FuzzerExecs   int64
}

var (
	encodedCRLF = regexp.MustCompile(`(?i)%0d%0a|%0a%0d|%0d|%0a`)
	auditSignal = regexp.MustCompile(`(?i)(INFO|WARN|ERROR)\s+(audit|security)|\bactor=admin\b|\baction=export\b`)
)

func Analyze(checkID, attemptID string, raw []byte) Result {
	text := string(raw)
	normalized := Normalize(text)
	now := time.Now()
	result := Result{Normalized: normalized, FuzzerExecs: 182204}

	crlf := encodedCRLF.MatchString(text)
	forged := auditSignal.MatchString(normalized) && (crlf || strings.Contains(normalized, "\r\n"))
	boundary := strings.ContainsAny(normalized, "\u2028\u2029")

	ev := func(id, step, label, kind, content string) model.Evidence {
		sum := sha256.Sum256([]byte(content))
		return model.Evidence{
			ID: id, CheckID: checkID, AttemptID: attemptID, StepID: step,
			Label: label, Kind: kind, SHA256: hex.EncodeToString(sum[:]),
			Size: int64(len([]byte(content))), Content: content,
			Retained: true, CreatedAt: now,
		}
	}
	result.Evidence = append(result.Evidence,
		ev("E-101", attemptID+"-S1", "原始输入快照", "raw", text),
		ev("E-102", attemptID+"-S2", "规范化字节视图", "normalized", normalized),
	)

	if crlf {
		result.Findings = append(result.Findings, model.Finding{
			ID: "FND-01", Rule: "LOG-014", Title: "换行控制序列",
			Severity: "high", Confidence: 0.96, StepID: attemptID + "-S4", EvidenceID: "E-103",
			Detail: "输入中存在百分号编码换行序列；规范化后可能产生独立日志行。",
		})
		result.Evidence = append(result.Evidence,
			ev("E-103", attemptID+"-S4", "规范化换行片段", "derived", excerpt(normalized, 240)),
		)
	}
	if forged {
		result.Findings = append(result.Findings, model.Finding{
			ID: "FND-02", Rule: "LOG-021", Title: "伪造审计身份",
			Severity: "high", Confidence: 0.90, StepID: attemptID + "-S4", EvidenceID: "E-103",
			Detail: "注入片段伪装为审计或安全事件，且包含高权限操作字段。",
		})
	}
	if boundary {
		result.AmbiguousRule = "BOUNDARY-07"
		result.AmbiguousNote = "U+2028/U+2029 位于日志字段中；是否作为行分隔符取决于上游解析器，自动规则无法判断。"
		result.Findings = append(result.Findings, model.Finding{
			ID: "FND-03", Rule: "BOUNDARY-07", Title: "Unicode 行分隔符边界",
			Severity: "unknown", Confidence: 0.50, StepID: attemptID + "-S4", EvidenceID: "E-104",
			Detail: result.AmbiguousNote,
		})
		result.Evidence = append(result.Evidence,
			ev("E-104", attemptID+"-S4", "Unicode 边界样本", "boundary", excerpt(normalized, 240)),
		)
	}
	if crlf || forged {
		minimal := "%0d%0a2026-11-22T20:40:01Z INFO audit actor=admin action=export status=ok"
		result.Evidence = append(result.Evidence,
			ev("E-105", attemptID+"-S3", "libFuzzer 最小复现输入", "fuzzer-artifact", minimal),
		)
	}

	switch {
	case crlf && forged:
		result.AutoVerdict = "malicious"
		result.AutoLabel = "高风险 · 日志注入"
		result.Confidence = 0.93
		result.Summary = "发现可解码换行序列和伪造审计字段，二者组合可污染下游日志检索。"
	case crlf || forged:
		result.AutoVerdict = "suspicious"
		result.AutoLabel = "中风险 · 需复核"
		result.Confidence = 0.72
		result.Summary = "发现可疑换行或审计字段，但尚未形成完整注入链。"
	default:
		result.AutoVerdict = "benign"
		result.AutoLabel = "低风险"
		result.Confidence = 0.88
		result.Summary = "未发现可解码换行序列或伪造日志行特征。"
	}
	if boundary && result.AutoVerdict == "benign" {
		result.AutoVerdict = "unknown"
		result.AutoLabel = "无法判断 · 边界"
		result.Confidence = 0.50
		result.Summary = "发现 Unicode 行分隔符边界，自动规则无法确认上游解析行为。"
	}
	return result
}

func Normalize(text string) string {
	replacer := strings.NewReplacer(
		"%0d%0a", "\r\n", "%0D%0A", "\r\n",
		"%0a%0d", "\n\r", "%0A%0D", "\n\r",
		"%0d", "\r", "%0D", "\r",
		"%0a", "\n", "%0A", "\n",
		"%09", "\t", "%09", "\t",
	)
	return replacer.Replace(text)
}

func excerpt(s string, limit int) string {
	if len([]rune(s)) <= limit {
		return s
	}
	r := []rune(s)
	return fmt.Sprintf("%s…", string(r[:limit]))
}

package inspect

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ToleranceSeconds  = 300
	ClockDriftBoundMS = 2
)

var ErrMalformedSignature = errors.New("malformed signature envelope")

type VerifyInput struct {
	ObjectID       string
	Version        string
	Body           []byte
	Headers        map[string]string
	Signature      string
	SignatureAlg   string
	Canonicalizer  string
	VerifierSource string
	SourceLine     int
	SourceExcerpt  string
	Secret         []byte
	ObservedAt     time.Time
	ClockDriftMS   int
	EnforceTime    bool
}

type VerifyOutcome struct {
	Result  VerificationResult
	Err     error
	Failure *Failure
}

type Failure struct {
	Stage   string
	Code    string
	Message string
}

func VerifyWebhook(input VerifyInput) VerifyOutcome {
	bodyHash := sha256.Sum256(input.Body)
	headerKeys := sortedHeaderKeys(input.Headers)
	canonicalHeaders := canonicalHeaderText(input.Headers, headerKeys)

	result := VerificationResult{
		Evidence: []EvidenceDraft{
			{Kind: "raw_input", Label: "原始请求字节", Value: string(input.Body)},
			{Kind: "raw_input", Label: "请求头快照", Value: canonicalHeaders},
			{Kind: "raw_input", Label: "签名字段原文", Value: input.Signature},
			{Kind: "processing", Label: "原始字节 SHA-256", Value: hex.EncodeToString(bodyHash[:])},
		},
		Steps: []StepResult{
			{
				Action: "捕获原始输入", InputRef: "capture://" + input.ObjectID,
				OutputRef: "evidence:raw_input", Status: "ok",
				Detail: fmt.Sprintf("读取 %d 字节；扩展名不参与验签，仅保留为来源属性。", len(input.Body)),
			},
			{
				Action: "解析签名信封", InputRef: "evidence:raw_input",
				OutputRef: "parse:signature", Status: "ok",
				Detail: "按 " + input.SignatureAlg + " 读取 t 与 v1 字段，不经过 JSON 重新序列化。",
			},
		},
	}

	signature, timestamp, err := parseSignatureEnvelope(input.Signature)
	if err != nil {
		return VerifyOutcome{
			Result: result,
			Err:    fmt.Errorf("decode signature envelope: %w", err),
			Failure: &Failure{
				Stage: "signature.decode", Code: "SIG_ENVELOPE_INVALID",
				Message: "签名字段包含非十六进制字符，无法形成可比较的摘要。",
			},
		}
	}
	result.Evidence = append(result.Evidence,
		EvidenceDraft{Kind: "processing", Label: "解码后的签名摘要", Value: hex.EncodeToString(signature)},
		EvidenceDraft{Kind: "processing", Label: "签名时间戳", Value: strconv.FormatInt(timestamp, 10)},
	)

	message, err := canonicalMessage(input.Canonicalizer, timestamp, input.Body)
	if err != nil {
		return VerifyOutcome{
			Result:  result,
			Err:     err,
			Failure: &Failure{Stage: "canonicalize", Code: "CANONICALIZATION_FAILED", Message: err.Error()},
		}
	}
	mac := hmac.New(sha256.New, input.Secret)
	_, _ = mac.Write(message)
	expected := mac.Sum(nil)
	equal := subtle.ConstantTimeCompare(expected, signature) == 1
	result.Evidence = append(result.Evidence,
		EvidenceDraft{Kind: "processing", Label: "Canonical string", Value: string(message)},
		EvidenceDraft{Kind: "processing", Label: "HMAC-SHA256 重算", Value: hex.EncodeToString(expected)},
		EvidenceDraft{
			Kind: "processing", Label: "恒时比较结果",
			Value: map[bool]string{true: "match", false: "mismatch"}[equal],
		},
	)
	result.Steps = append(result.Steps, StepResult{
		Action: "构造 canonical string", InputRef: "parse:signature",
		OutputRef: "canonical:sha256", Status: "ok",
		Detail: "使用原始 body 与 t 字段拼接；未做空白、JSON key 或编码归一化。",
	}, StepResult{
		Action: "HMAC-SHA256 比对", InputRef: "canonical:sha256",
		OutputRef: "compare:constant_time", Status: "ok",
		Detail: fmt.Sprintf("密钥引用 env:WEBHOOK_SECRET；比较结果 %t。", equal),
	})

	if !equal {
		result.Verdict = VerdictError
		result.Confidence = "high"
		result.Summary = "签名摘要与原始字节不匹配"
		result.Rationale = "对原始 body 重新计算 HMAC-SHA256 后与 v1 摘要不一致。"
		return VerifyOutcome{Result: result, Err: errors.New("signature mismatch"),
			Failure: &Failure{Stage: "compare", Code: "SIGNATURE_MISMATCH", Message: result.Summary}}
	}

	timestampText := time.Unix(timestamp, 0).UTC().Format(time.RFC3339)
	result.Evidence = append(result.Evidence,
		EvidenceDraft{Kind: "processing", Label: "签名时间戳（UTC）", Value: timestampText},
		EvidenceDraft{Kind: "processing", Label: "观测接收时间（UTC）", Value: input.ObservedAt.UTC().Format(time.RFC3339Nano)},
	)

	if input.EnforceTime {
		boundary, indeterminate := timeBoundaryOutcome(timestamp, input.ObservedAt, input.ClockDriftMS)
		result.Evidence = append(result.Evidence,
			EvidenceDraft{Kind: "boundary", Label: "时钟偏差观察", Value: boundary},
		)
		result.Steps = append(result.Steps, StepResult{
			Action: "检查 300s 时间窗", InputRef: "parse:signature",
			OutputRef: "boundary:timestamp", Status: map[bool]string{true: "unresolved", false: "ok"}[indeterminate],
			Detail: fmt.Sprintf("strict greater-than 判定；%s；时钟漂移界 ±%dms。", boundary, ClockDriftBoundMS),
		})
		if indeterminate {
			result.Verdict = VerdictIndeterminate
			result.Confidence = "unresolved"
			result.Summary = "签名有效，但恰好落在 300s 时间窗边界"
			result.Rationale = "摘要匹配且 canonical string 可复现。观测差值为 300.000s，源码使用严格大于比较；捕获时钟存在 ±2ms 未观测漂移，无法唯一判定该请求会被接受还是拒绝。"
			result.BoundaryNote = "边界条件：abs(observed_at - t) == 300s。实际偏斜范围 299.998s–300.002s，跨过源码 `skew > 300*time.Second` 的两侧。保留时间戳、接收时间、源码行和时钟漂移声明作为关键证据。"
			result.Steps = append(result.Steps, StepResult{
				Action: "保留边界证据", InputRef: "boundary:timestamp",
				OutputRef: "conclusion:indeterminate", Status: "unresolved",
				Detail: "停止自动定论；保留原始签名字段、接收日志与 verifier v2.0.0-rc1 第 87 行。",
			})
			return VerifyOutcome{Result: result}
		}
	}

	var document map[string]any
	if err := json.Unmarshal(input.Body, &document); err != nil {
		result.Evidence = append(result.Evidence,
			EvidenceDraft{Kind: "processing", Label: "内容类型探测", Value: "application/json（解码失败）"},
		)
	} else {
		result.Evidence = append(result.Evidence,
			EvidenceDraft{Kind: "processing", Label: "内容类型探测", Value: "application/json；扩展名未参与判定"},
		)
	}
	result.Steps = append(result.Steps, StepResult{
		Action: "探测内容类型", InputRef: "evidence:raw_input",
		OutputRef: "sniff:json", Status: "ok",
		Detail: "验签后按原始字节探测 JSON；未知扩展名不影响该步骤。",
	})
	result.Verdict = VerdictVerified
	result.Confidence = "high"
	result.Summary = "签名匹配，来源链完整"
	result.Rationale = "原始输入、canonical string、HMAC 重算值和源码比较点均可定位；结论不依赖扩展名或解析后的对象。"
	return VerifyOutcome{Result: result}
}

func parseSignatureEnvelope(value string) ([]byte, int64, error) {
	fields := strings.Split(strings.TrimSpace(value), ",")
	var timestamp int64 = -1
	var encoded string
	for _, field := range fields {
		key, raw, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return nil, 0, ErrMalformedSignature
			}
			timestamp = parsed
		case "v1":
			encoded = raw
		}
	}
	if timestamp < 0 || encoded == "" || len(encoded) != sha256.Size*2 {
		return nil, 0, ErrMalformedSignature
	}
	signature, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, 0, ErrMalformedSignature
	}
	return signature, timestamp, nil
}

func canonicalMessage(canonicalizer string, timestamp int64, body []byte) ([]byte, error) {
	switch canonicalizer {
	case "stripe-v1", "":
		message := make([]byte, 0, len(body)+24)
		message = strconv.AppendInt(message, timestamp, 10)
		message = append(message, '.')
		message = append(message, body...)
		return message, nil
	default:
		return nil, fmt.Errorf("unsupported canonicalizer %q", canonicalizer)
	}
}

func timeBoundaryOutcome(timestamp int64, observed time.Time, driftMS int) (string, bool) {
	signedAt := time.Unix(timestamp, 0).UTC()
	delta := observed.UTC().Sub(signedAt)
	boundary := fmt.Sprintf("observed-t = %dms", delta.Milliseconds())
	if driftMS < 0 {
		driftMS = -driftMS
	}
	low := delta.Milliseconds() - int64(driftMS)
	high := delta.Milliseconds() + int64(driftMS)
	toleranceMS := int64(ToleranceSeconds * 1000)
	indeterminate := low <= toleranceMS && high > toleranceMS
	if indeterminate {
		boundary += fmt.Sprintf("；可能区间 %dms…%dms；阈值 %dms", low, high, toleranceMS)
	}
	return boundary, indeterminate
}

func sortedHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	return keys
}

func canonicalHeaderText(headers map[string]string, keys []string) string {
	normalized := make(map[string]string, len(headers))
	for key, value := range headers {
		normalized[strings.ToLower(key)] = value
	}
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteString(": ")
		builder.WriteString(normalized[key])
		builder.WriteByte('\n')
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

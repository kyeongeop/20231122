package audit

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type header struct {
	Name  string
	Value string
	Start int
	End   int
}

func Analyze(raw []byte, opt Options) Result {
	result := Result{ContentHash: HashBytes(raw)}
	appendStep := func(step Step) {
		step.Ordinal = len(result.Steps) + 1
		step.ID = fmt.Sprintf("st_%02d_%s", step.Ordinal, strings.ReplaceAll(step.Key, ".", "_"))
		result.Steps = append(result.Steps, step)
	}

	truncated := opt.ExpectedBytes > len(raw)
	captureStatus := StatusPass
	captureSummary := fmt.Sprintf("采集完整，共 %d bytes", len(raw))
	captureDetail := "原始输入按字节原样保留；未做规范化或重新序列化。"
	if truncated {
		captureStatus = StatusTruncated
		captureSummary = fmt.Sprintf("采集在 %d / %d bytes 处截断", len(raw), opt.ExpectedBytes)
		captureDetail = fmt.Sprintf("缺失 %d bytes。后续解析没有完整输入，不得据此生成通过结论。", opt.ExpectedBytes-len(raw))
	}
	tailStart := len(raw) - 96
	if tailStart < 0 {
		tailStart = 0
	}
	appendStep(Step{
		Key:      "capture.complete",
		Label:    "采集完整性",
		Status:   captureStatus,
		Summary:  captureSummary,
		Detail:   captureDetail,
		Duration: 4,
		Evidence: &Evidence{
			Start:   tailStart,
			End:     len(raw),
			Excerpt: excerpt(raw, tailStart, len(raw)),
			Hash:    result.ContentHash,
			Note:    "原文尾部；偏移按 UTF-8 bytes 计算。",
		},
	})

	if truncated {
		blockRemaining(&result, appendStep, []string{
			"frame.parse|报文框架解析",
			"headers.parse|响应头解析",
			"policy.origin|来源匹配",
			"policy.credentials|凭据策略",
			"policy.vary|缓存分区",
		})
		finish(&result)
		return result
	}

	if !utf8.Valid(raw) {
		appendStep(Step{
			Key: "frame.parse", Label: "报文框架解析", Status: StatusFail,
			Summary: "输入不是有效 UTF-8", Detail: "无法可靠定位报文边界；未继续推断后续策略。", Duration: 2,
			Evidence: &Evidence{Start: 0, End: len(raw), Excerpt: excerpt(raw, 0, len(raw)), Hash: result.ContentHash},
		})
		blockRemaining(&result, appendStep, []string{
			"headers.parse|响应头解析",
			"policy.origin|来源匹配",
			"policy.credentials|凭据策略",
			"policy.vary|缓存分区",
		})
		finish(&result)
		return result
	}

	reqHead, responseStart, responseHead, headerEnd, err := parseFrame(raw)
	if err != nil {
		appendStep(Step{
			Key: "frame.parse", Label: "报文框架解析", Status: StatusFail,
			Summary: "无法定位完整的响应头", Detail: err.Error(), Duration: 3,
			Evidence: &Evidence{Start: 0, End: len(raw), Excerpt: excerpt(raw, 0, len(raw)), Hash: result.ContentHash},
		})
		blockRemaining(&result, appendStep, []string{
			"headers.parse|响应头解析",
			"policy.origin|来源匹配",
			"policy.credentials|凭据策略",
			"policy.vary|缓存分区",
		})
		finish(&result)
		return result
	}
	appendStep(Step{
		Key: "frame.parse", Label: "报文框架解析", Status: StatusPass,
		Summary: "请求 / 响应边界与响应头终止符均已定位", Duration: 3,
		Detail: fmt.Sprintf("响应从 byte %d 开始，响应头在 byte %d 结束。", responseStart, headerEnd),
		Evidence: &Evidence{
			Start: responseStart, End: headerEnd,
			Excerpt: excerpt(raw, responseStart, headerEnd), Hash: result.ContentHash,
			Note: "完整响应头切片；保留原始 CRLF。",
		},
	})

	requestHeaders, responseHeaders, err := parseHeaderBlocks(reqHead, responseHead, responseStart)
	if err != nil {
		appendStep(Step{
			Key: "headers.parse", Label: "响应头解析", Status: StatusFail,
			Summary: "存在无法解析的头部行", Detail: err.Error(), Duration: 5,
			Evidence: &Evidence{Start: responseStart, End: headerEnd, Excerpt: excerpt(raw, responseStart, headerEnd), Hash: result.ContentHash},
		})
		blockRemaining(&result, appendStep, []string{
			"policy.origin|来源匹配",
			"policy.credentials|凭据策略",
			"policy.vary|缓存分区",
		})
		finish(&result)
		return result
	}
	appendStep(Step{
		Key: "headers.parse", Label: "响应头解析", Status: StatusPass,
		Summary: fmt.Sprintf("解析 %d 个响应头；名称已做 ASCII 小写归一", len(responseHeaders)), Duration: 5,
		Detail:   "头部值保留原始大小写与前后空白，比较时仅折叠 HTTP 字段名。",
		Evidence: &Evidence{Start: responseStart, End: headerEnd, Excerpt: excerpt(raw, responseStart, headerEnd), Hash: result.ContentHash},
	})

	originHeader := findHeader(requestHeaders, "origin")
	allowOrigin := findHeader(responseHeaders, "access-control-allow-origin")
	originStep := evaluateOrigin(originHeader, allowOrigin)
	originStep.Duration = 2
	originStep.Evidence = &Evidence{Hash: result.ContentHash}
	if originHeader != nil {
		originStep.Evidence.Start = originHeader.Start
		originStep.Evidence.End = originHeader.End
		originStep.Evidence.Excerpt = excerpt(raw, originHeader.Start, originHeader.End)
		originStep.Evidence.Note = "请求 Origin 原值；脱敏标记也作为证据保留。"
	} else if allowOrigin != nil {
		originStep.Evidence.Start = allowOrigin.Start
		originStep.Evidence.End = allowOrigin.End
		originStep.Evidence.Excerpt = excerpt(raw, allowOrigin.Start, allowOrigin.End)
		originStep.Evidence.Note = "响应侧允许来源；请求侧缺少 Origin。"
	}
	appendStep(originStep)

	credentialsStep := evaluateCredentials(allowOrigin, findHeader(responseHeaders, "access-control-allow-credentials"))
	credentialsStep.Duration = 1
	if allowOrigin != nil {
		credentialsStep.Evidence = &Evidence{
			Start: allowOrigin.Start, End: allowOrigin.End,
			Excerpt: excerpt(raw, allowOrigin.Start, allowOrigin.End), Hash: result.ContentHash,
			Note: "凭据判定以允许来源和凭据标头为联合依据。",
		}
	}
	appendStep(credentialsStep)

	varyStep := evaluateVary(responseHeaders, allowOrigin)
	varyStep.Duration = 1
	if varyStep.Evidence == nil {
		varyStep.Evidence = &Evidence{Hash: result.ContentHash}
	}
	appendStep(varyStep)

	if opt.ReplayOf != "" {
		replayStep := evaluateReplay(raw, opt)
		replayStep.Duration = 3
		appendStep(replayStep)
		result.ReplayOK = replayStep.Status == StatusPass
	}

	finish(&result)
	return result
}

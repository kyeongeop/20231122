package audit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func blockRemaining(result *Result, appendStep func(Step), definitions []string) {
	for _, definition := range definitions {
		parts := strings.SplitN(definition, "|", 2)
		appendStep(Step{
			Key: parts[0], Label: parts[1], Status: StatusBlocked,
			Summary: "上游输入不完整，状态阻断",
			Detail:  "未执行判断；该状态不能计为通过，也不能用于得出合规结论。",
		})
	}
}

func finish(result *Result) {
	for i := range result.Steps {
		if result.Steps[i].Evidence != nil && result.Steps[i].Evidence.Hash == "" {
			result.Steps[i].Evidence.Hash = result.ContentHash
		}
		switch result.Steps[i].Status {
		case StatusPass:
			result.Counts.Pass++
		case StatusFail:
			result.Counts.Fail++
			if result.FirstError == nil {
				result.FirstError = &result.Steps[i]
			}
		case StatusUndecided:
			result.Counts.Undecided++
			if result.Boundary == nil {
				result.Boundary = &result.Steps[i]
			}
		case StatusBlocked:
			result.Counts.Blocked++
		case StatusTruncated:
			result.Counts.Truncated++
			if result.FirstError == nil {
				result.FirstError = &result.Steps[i]
			}
		}
	}
}

func parseFrame(raw []byte) (reqHead []byte, responseStart int, responseHead []byte, headerEnd int, err error) {
	requestEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	sepLen := 4
	if requestEnd < 0 {
		requestEnd = bytes.Index(raw, []byte("\n\n"))
		sepLen = 2
	}
	if requestEnd < 0 {
		return nil, 0, nil, 0, errors.New("未找到请求头终止符")
	}
	reqHead = raw[:requestEnd]
	searchFrom := requestEnd + sepLen
	idx := bytes.Index(raw[searchFrom:], []byte("HTTP/1."))
	if idx < 0 {
		return nil, 0, nil, 0, errors.New("未找到 HTTP 响应起始行")
	}
	responseStart = searchFrom + idx
	headEndRel := bytes.Index(raw[responseStart:], []byte("\r\n\r\n"))
	headerSep := 4
	if headEndRel < 0 {
		headEndRel = bytes.Index(raw[responseStart:], []byte("\n\n"))
		headerSep = 2
	}
	if headEndRel < 0 {
		return nil, 0, nil, 0, errors.New("响应头缺少终止符或响应被截断")
	}
	headerEnd = responseStart + headEndRel + headerSep
	responseHead = raw[responseStart : headerEnd-headerSep]
	return reqHead, responseStart, responseHead, headerEnd, nil
}

func parseHeaderBlocks(reqHead, responseHead []byte, responseStart int) ([]header, []header, error) {
	req, err := parseHeaders(reqHead, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("请求头: %w", err)
	}
	resp, err := parseHeaders(responseHead, responseStart)
	if err != nil {
		return nil, nil, fmt.Errorf("响应头: %w", err)
	}
	return req, resp, nil
}

func parseHeaders(block []byte, base int) ([]header, error) {
	lines := bytes.Split(block, []byte("\n"))
	headers := make([]header, 0, len(lines))
	offset := base
	for i, line := range lines {
		lineStart := offset
		offset += len(line) + 1
		line = bytes.TrimSuffix(line, []byte("\r"))
		if i == 0 && len(lines) > 1 {
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("第 %d 行缺少字段名或冒号: %q", i+1, string(line))
		}
		name := strings.TrimSpace(string(line[:colon]))
		value := strings.TrimSpace(string(line[colon+1:]))
		if name == "" {
			return nil, fmt.Errorf("第 %d 行字段名为空", i+1)
		}
		valueStart := lineStart + colon + 1
		for valueStart < lineStart+len(line) && (line[valueStart-lineStart] == ' ' || line[valueStart-lineStart] == '\t') {
			valueStart++
		}
		headers = append(headers, header{
			Name: strings.ToLower(name), Value: value,
			Start: valueStart, End: lineStart + len(line),
		})
	}
	return headers, nil
}

func findHeader(headers []header, name string) *header {
	for i := range headers {
		if headers[i].Name == name {
			return &headers[i]
		}
	}
	return nil
}

func evaluateOrigin(origin, allowOrigin *header) Step {
	step := Step{Key: "policy.origin", Label: "来源匹配"}
	if origin == nil {
		step.Status = StatusUndecided
		step.Summary = "无法判断：请求侧 Origin 缺失"
		step.Detail = "没有调用方来源，不能断言允许来源是否匹配；该边界不计入通过。"
		return step
	}
	if strings.Contains(strings.ToUpper(origin.Value), "REDACTED") {
		step.Status = StatusUndecided
		step.Summary = "无法判断：请求 Origin 已脱敏"
		step.Detail = "脱敏策略保留了字段名和位置，但去掉了来源主体。来源等价性无法可靠证明，需回到未脱敏源或人工复核。"
		return step
	}
	if allowOrigin == nil {
		step.Status = StatusFail
		step.Summary = "缺少 Access-Control-Allow-Origin"
		step.Detail = "响应没有声明允许来源，浏览器不会暴露跨域响应。"
		return step
	}
	allowed := strings.TrimSpace(allowOrigin.Value)
	if strings.EqualFold(allowed, "null") || strings.EqualFold(origin.Value, "null") {
		step.Status = StatusUndecided
		step.Summary = "无法判断：opaque origin 的等价性"
		step.Detail = "null / opaque origin 不携带可验证的 principal 边界；仅凭字符串相等不足以确认信任关系。"
		return step
	}
	if allowed == "*" || allowed == origin.Value {
		step.Status = StatusPass
		step.Summary = "允许来源覆盖请求 Origin"
		step.Detail = fmt.Sprintf("请求 Origin=%q；响应允许来源=%q。", origin.Value, allowed)
		return step
	}
	step.Status = StatusFail
	step.Summary = "请求 Origin 不在允许来源内"
	step.Detail = fmt.Sprintf("请求 Origin=%q；响应允许来源=%q。", origin.Value, allowed)
	return step
}

func evaluateCredentials(allowOrigin, credentials *header) Step {
	step := Step{Key: "policy.credentials", Label: "凭据策略"}
	if allowOrigin == nil {
		step.Status = StatusBlocked
		step.Summary = "缺少允许来源，凭据组合未判断"
		step.Detail = "上游结论不足，不能计算凭据可用性。"
		return step
	}
	allowValue := strings.TrimSpace(allowOrigin.Value)
	credentialsOn := credentials != nil && strings.EqualFold(strings.TrimSpace(credentials.Value), "true")
	if credentialsOn && allowValue == "*" {
		step.Status = StatusFail
		step.Summary = "通配符来源与凭据同时启用"
		step.Detail = "Access-Control-Allow-Origin=* 不能与 Access-Control-Allow-Credentials: true 组合用于携带凭据的请求。"
		return step
	}
	step.Status = StatusPass
	if credentialsOn {
		step.Summary = "允许来源为具体来源，且凭据已启用"
	} else {
		step.Summary = "未声明凭据，组合不产生冲突"
	}
	step.Detail = fmt.Sprintf("Access-Control-Allow-Origin=%q；Access-Control-Allow-Credentials=%v。", allowValue, credentialsOn)
	return step
}

func evaluateVary(responseHeaders []header, allowOrigin *header) Step {
	step := Step{Key: "policy.vary", Label: "缓存分区"}
	if allowOrigin == nil {
		step.Status = StatusBlocked
		step.Summary = "缺少允许来源，缓存分区未判断"
		return step
	}
	var vary *header
	for i := range responseHeaders {
		if responseHeaders[i].Name == "vary" {
			vary = &responseHeaders[i]
			break
		}
	}
	if vary == nil {
		step.Status = StatusFail
		step.Summary = "缺少 Vary: Origin"
		step.Detail = "响应按具体 Origin 生成 CORS 判定，但缓存键没有包含 Origin，共享缓存可能把一处来源的策略复用给另一处来源。"
		step.Evidence = &Evidence{
			Start: allowOrigin.Start, End: allowOrigin.End,
			Excerpt: excerptAt(allowOrigin), Note: "允许来源原文；同响应中没有任何 Vary 字段。",
		}
		return step
	}
	hasOrigin := false
	for _, token := range strings.Split(vary.Value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "origin") {
			hasOrigin = true
			break
		}
	}
	if hasOrigin {
		step.Status = StatusPass
		step.Summary = "缓存键包含 Origin"
		step.Detail = fmt.Sprintf("Vary=%q，可区分不同来源的 CORS 响应。", vary.Value)
	} else {
		step.Status = StatusFail
		step.Summary = "Vary 未包含 Origin"
		step.Detail = fmt.Sprintf("Vary=%q；按具体来源变化的 CORS 头未进入缓存键。", vary.Value)
	}
	step.Evidence = &Evidence{
		Start: vary.Start, End: vary.End, Excerpt: excerptAt(vary),
		Note: "Vary 字段原值。",
	}
	return step
}

func evaluateReplay(raw []byte, opt Options) Step {
	step := Step{Key: "replay.verify", Label: "重放接缝校验"}
	if opt.RecoveredFrom <= 0 || opt.RecoveredFrom > len(raw) {
		step.Status = StatusFail
		step.Summary = "恢复接缝偏移无效"
		step.Detail = fmt.Sprintf("恢复起点 %d 不在输入范围 0..%d 内。", opt.RecoveredFrom, len(raw))
		return step
	}
	start := opt.RecoveredFrom - 32
	if start < 0 {
		start = 0
	}
	end := opt.RecoveredFrom + 64
	if end > len(raw) {
		end = len(raw)
	}
	step.Status = StatusPass
	step.Summary = fmt.Sprintf("前缀 %d bytes 与恢复块可拼接", opt.RecoveredFrom)
	step.Detail = "重放不覆盖截断记录；原始前缀、恢复块和拼接后全文分别保留哈希。"
	step.Evidence = &Evidence{
		Start: start, End: end, Excerpt: excerpt(raw, start, end),
		Note: "接缝两侧各保留一段上下文，便于核对恢复边界。",
	}
	return step
}

func excerptAt(value *header) string {
	if value == nil {
		return ""
	}
	if value.End-value.Start > 220 {
		return value.Value[:217] + "..."
	}
	return value.Value
}

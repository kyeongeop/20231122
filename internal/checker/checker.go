// Package checker evaluates WebSocket authorization-bypass test cases and
// produces verdicts with a full processing-step lineage so every conclusion
// can be traced back to the original input.
package checker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Verdict is the outcome of evaluating one test input.
type Verdict string

const (
	VerdictBypassDetected Verdict = "bypass_detected"
	VerdictNoBypass       Verdict = "no_bypass"
	VerdictUndetermined   Verdict = "undetermined"
)

// Input is the original raw test-case input. Content is the canonical text
// form: key: value lines describing one handshake scenario.
type Input struct {
	Label   string
	Content string
}

// Digest returns the SHA-256 of the original content, used as the stable
// anchor every conclusion traces back to.
func (in Input) Digest() string {
	sum := sha256.Sum256([]byte(in.Content))
	return hex.EncodeToString(sum[:])
}

// Step is one recorded processing step in the lineage chain.
type Step struct {
	Name   string
	Detail string
}

// Result is the automated evaluation of one input.
type Result struct {
	Verdict   Verdict
	Rationale string
	Steps     []Step
	// Evidence holds key artifacts worth keeping (notably for undetermined
	// edge cases), e.g. truncated captures or ambiguous policy text.
	Evidence map[string]string
}

// scenario is the parsed form of an input.
type scenario struct {
	policyAuthRequired bool
	policyKnown        bool
	credentialSent     bool
	statusCode         int
	statusKnown        bool
	upgradeAccepted    bool
	connectionDropped  bool
	captureTruncated   bool
}

func parseScenario(content string) (scenario, []Step) {
	var sc scenario
	var steps []Step
	recognized := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToLower(strings.TrimSpace(value))
		recognized++
		switch key {
		case "policy.auth_required":
			sc.policyKnown = true
			sc.policyAuthRequired = value == "true" || value == "yes"
		case "request.credential":
			sc.credentialSent = value != "" && value != "none"
		case "response.status":
			var code int
			if _, err := fmt.Sscanf(value, "%d", &code); err == nil && code > 0 {
				sc.statusKnown = true
				sc.statusCode = code
				sc.upgradeAccepted = code == 101
			}
		case "response.connection":
			sc.connectionDropped = value == "reset" || value == "dropped"
		case "capture.truncated":
			sc.captureTruncated = value == "true" || value == "yes"
		}
	}
	steps = append(steps, Step{
		Name:   "parse",
		Detail: fmt.Sprintf("recognized %d directive lines from original input", recognized),
	})
	return sc, steps
}

// Evaluate runs the full processing pipeline for one input and records each
// step so the conclusion can be replayed and audited.
func Evaluate(in Input) Result {
	res := Result{Evidence: map[string]string{}}

	sc, steps := parseScenario(in.Content)
	res.Steps = append(res.Steps, steps...)

	res.Steps = append(res.Steps, Step{
		Name: "normalize",
		Detail: fmt.Sprintf("policy_known=%t auth_required=%t credential_sent=%t status_known=%t status=%d dropped=%t truncated=%t",
			sc.policyKnown, sc.policyAuthRequired, sc.credentialSent,
			sc.statusKnown, sc.statusCode, sc.connectionDropped, sc.captureTruncated),
	})

	classify := Step{Name: "classify"}
	switch {
	case !sc.statusKnown && sc.connectionDropped:
		// Edge case: the capture was interrupted (e.g. mid-run cancellation)
		// before any status line arrived. We cannot tell whether the server
		// would have accepted the upgrade, so the verdict is undetermined and
		// the partial capture is kept as key evidence.
		classify.Detail = "no status line observed; connection dropped before response completed"
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：连接在响应完成前中断，缺少状态行，无法确认服务端是否会放行未授权升级"
		res.Evidence["partial_capture"] = in.Content
		res.Evidence["drop_reason"] = "connection reset/dropped before HTTP status line"
	case sc.captureTruncated:
		classify.Detail = "capture flagged truncated; response bytes are incomplete"
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：抓包数据被截断，响应不完整，结论不可靠"
		res.Evidence["partial_capture"] = in.Content
	case sc.upgradeAccepted && !sc.credentialSent && sc.policyKnown && sc.policyAuthRequired:
		classify.Detail = "101 accepted without credentials while policy requires auth"
		res.Verdict = VerdictBypassDetected
		res.Rationale = "检测到授权绕过：策略要求认证，但未携带凭证的握手仍收到 101 Switching Protocols"
	case sc.upgradeAccepted && !sc.credentialSent && !sc.policyKnown:
		classify.Detail = "101 accepted without credentials, but endpoint auth policy is unknown"
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：未授权握手被接受，但端点授权策略未知，无法确认是否构成绕过"
		res.Evidence["ambiguous_policy"] = "policy.auth_required directive missing from input"
	case sc.upgradeAccepted:
		classify.Detail = "101 accepted with credentials presented"
		res.Verdict = VerdictNoBypass
		res.Rationale = "未发现绕过：握手携带凭证，升级被接受属预期行为"
	case sc.statusKnown && (sc.statusCode == 401 || sc.statusCode == 403):
		classify.Detail = fmt.Sprintf("server rejected unauthenticated upgrade with %d", sc.statusCode)
		res.Verdict = VerdictNoBypass
		res.Rationale = fmt.Sprintf("未发现绕过：未授权握手被拒绝（HTTP %d）", sc.statusCode)
	case sc.statusKnown:
		classify.Detail = fmt.Sprintf("unexpected status %d does not match accept/reject patterns", sc.statusCode)
		res.Verdict = VerdictUndetermined
		res.Rationale = fmt.Sprintf("无法判断：状态码 %d 不在预期集合（101/401/403）内，需人工研判", sc.statusCode)
		res.Evidence["unexpected_status"] = fmt.Sprintf("%d", sc.statusCode)
	default:
		classify.Detail = "insufficient signals to classify"
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：输入信号不足"
	}
	res.Steps = append(res.Steps, classify)

	res.Steps = append(res.Steps, Step{
		Name:   "conclude",
		Detail: fmt.Sprintf("verdict=%s", res.Verdict),
	})
	return res
}

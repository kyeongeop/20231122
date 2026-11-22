package quota

import (
	"fmt"

	"quotabypass/internal/model"
)

// 触发位置与参考证据保持一致，保证攻击输入、权限判断与日志可相互对应。
const (
	GateFile     = "internal/quota/gate.go"
	GateLine     = 51
	GateFunction = "quotabypass/internal/quota.(*Gate).Decide"

	RunnerFile     = "internal/quota/runner.go"
	RunnerLine     = 68
	RunnerFunction = "quotabypass/internal/quota.InvalidResult"

	PolicyReserve  = "quota.concurrent.reserve"
	PolicyFragment = "quota.rejection_fragment.required"
)

// Gate 模拟并发配额预留门。remaining 为剩余配额，
// 每放行一个请求即原子扣减 1。
type Gate struct {
	remaining int
}

func NewGate(quotaCount int) *Gate { return &Gate{remaining: quotaCount} }

// Decide 对单个请求做权限判断。
//
// 拒绝响应缺少 fragment 时：
//   - mode == "vulnerable"：fail-open，放行（资源配额绕过）；
//   - mode == "fixed"：fail-closed，返回 400 拒绝。
//
// fragment 完整时按剩余配额判定：有余额放行 200，耗尽则用拒绝模板拒绝。
func (g *Gate) Decide(mode string, input model.AttackInput, fragmentMissing bool) (decision string, status int, reason, response string) {
	if fragmentMissing {
		if mode == ModeVulnerable {
			return "allow", 200,
				"missing rejection fragment: fail-open",
				`{"request_id":"%s","status":"allowed"}`
		}
		return "deny", 400,
			"missing rejection fragment: fail-closed",
			`{"error":"invalid_rejection_response","request_id":"%s"}`
	}

	if g.remaining > 0 {
		g.remaining--
		return "allow", 200,
			"quota reserved",
			`{"request_id":"%s","status":"allowed"}`
	}

	return "deny", input.RejectionResponse.Status,
		"quota exhausted",
		input.RejectionResponse.Body
}

// gateTrigger 返回权限判断点的触发器。
func gateTrigger() model.Trigger {
	return model.Trigger{File: GateFile, Line: GateLine, Function: GateFunction}
}

func runnerTrigger() model.Trigger {
	return model.Trigger{File: RunnerFile, Line: RunnerLine, Function: RunnerFunction}
}

// allowResponse 填充请求 ID 生成放行响应体。
func allowResponse(template, requestID string) string {
	return fmt.Sprintf(template, requestID)
}

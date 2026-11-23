package callback

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Validator 按固定顺序执行检查并留下完整事件链。
type Validator struct {
	policy *Policy
	now    func() time.Time
}

func NewValidator(p *Policy) *Validator {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Validator{policy: p, now: func() time.Time { return time.Now().UTC() }}
}

// Validate 执行完整流水线。任何阶段拒绝都会短路，但事件链保持完整。
func (v *Validator) Validate(caseID string, cb *Callback) *Outcome {
	out := &Outcome{
		CaseID:    caseID,
		Format:    cb.Format,
		InputHash: hashBytes(cb.Raw),
		Events:    []Event{},
	}
	seq := 0
	emit := func(stage Stage, check string, passed bool, verdict Verdict, code, detail, evidence string) Event {
		seq++
		ev := Event{
			Seq: seq, CaseID: caseID, Stage: stage, Check: check,
			Passed: passed, Verdict: verdict, ReasonCode: code,
			Detail: detail, Evidence: evidence, At: v.now(),
		}
		out.Events = append(out.Events, ev)
		return ev
	}
	deny := func(stage Stage, code, human string) *Outcome {
		out.TriggerPoint = stage
		out.Decision = Decision{Verdict: VerdictDeny, Stage: stage, ReasonCode: code, ReasonHuman: human}
		out.PermissionLog = "rule." + code
		return out
	}

	// 1. 中途取消（错误回调）优先识别：取消不是攻击，也不是放行。
	if cb.Error != "" {
		emit(StageCancellation, "error_present", true, VerdictCancelled,
			"cancellation.error_callback",
			fmt.Sprintf("error=%q description=%q", cb.Error, cb.ErrorDesc),
			out.InputHash)
		record, bound := v.policy.StateBinding[cb.State]
		if bound && record.Cancelled {
			emit(StageCancellation, "state_cancel_flag", true, VerdictCancelled,
				"cancellation.state_flag_confirmed",
				"server-side state record carries cancelled=true", out.InputHash)
		} else {
			emit(StageCancellation, "state_cancel_flag", false, VerdictIndeterminate,
				"cancellation.state_flag_missing",
				"error callback without matching server-side cancel flag", out.InputHash)
		}
		out.TriggerPoint = StageCancellation
		out.Decision = Decision{
			Verdict:     VerdictCancelled,
			Stage:       StageCancellation,
			ReasonCode:  "cancellation.error_callback",
			ReasonHuman: "resource owner cancelled mid-flow; no token exchange attempted",
		}
		out.PermissionLog = "rule.cancellation.error_callback"
		return out
	}

	// 1b. HTTP 参数污染：任何重复参数都视为篡改尝试，保留重复值证据。
	for field, joined := range cb.Fields {
		if len(field) > 9 && field[len(field)-9:] == ".repeated" {
			emit(StageParse, "parameter_pollution", false, VerdictDeny,
				"parse.duplicate_parameter",
				field+" values="+joined, out.InputHash)
			return deny(StageParse, "parse.duplicate_parameter",
				"duplicate parameter "+field)
		}
	}

	// 2. state 会话绑定（含重放检测）。
	record, bound := v.policy.StateBinding[cb.State]
	if !bound {
		emit(StageState, "state_binding", false, VerdictDeny,
			"state.unbound", "state has no server-side session binding", out.InputHash)
		return deny(StageState, "state.unbound", "state not bound to any session")
	}
	if record.Consumed {
		emit(StageState, "state_replay", false, VerdictDeny,
			"state.replayed", "state was already consumed", out.InputHash)
		return deny(StageState, "state.replayed", "replay of consumed state")
	}
	emit(StageState, "state_binding", true, VerdictAllow,
		"", "bound to session "+record.SessionID, out.InputHash)

	// 3. redirect_uri 精确匹配。
	ok, rule := v.policy.redirectURIAllowed(cb.RedirectURI)
	if !ok {
		emit(StageRedirectURI, "redirect_uri_exact_match", false, VerdictDeny,
			rule, "candidate="+cb.RedirectURI, out.InputHash)
		return deny(StageRedirectURI, rule, "redirect_uri failed "+rule)
	}
	if record.RedirectURI != "" && record.RedirectURI != cb.RedirectURI {
		emit(StageRedirectURI, "redirect_uri_session_match", false, VerdictDeny,
			"redirect_uri.session_mismatch",
			"session bound to "+record.RedirectURI, out.InputHash)
		return deny(StageRedirectURI, "redirect_uri.session_mismatch",
			"redirect_uri differs from session binding")
	}
	emit(StageRedirectURI, "redirect_uri_exact_match", true, VerdictAllow,
		"", rule, out.InputHash)

	// 4. 授权码形态检查。
	if cb.Code == "" {
		emit(StageCode, "code_present", false, VerdictDeny,
			"code.missing", "authorization code absent", out.InputHash)
		return deny(StageCode, "code.missing", "missing authorization code")
	}
	if len(cb.Code) > v.policy.MaxCodeLength {
		emit(StageCode, "code_length", false, VerdictDeny,
			"code.too_long",
			fmt.Sprintf("length=%d limit=%d", len(cb.Code), v.policy.MaxCodeLength),
			out.InputHash)
		return deny(StageCode, "code.too_long", "authorization code exceeds length limit")
	}
	emit(StageCode, "code_shape", true, VerdictAllow,
		"", fmt.Sprintf("length=%d", len(cb.Code)), out.InputHash)

	// 5. 新格式专属检查：issuer / response_mode / token_hash。
	if cb.Format == FormatV2 {
		ok, rule = v.policy.issuerAllowed(cb.Issuer)
		if !ok {
			emit(StageIssuer, "issuer_allowlist", false, VerdictDeny,
				rule, "iss="+cb.Issuer, out.InputHash)
			return deny(StageIssuer, rule, "issuer failed "+rule)
		}
		emit(StageIssuer, "issuer_allowlist", true, VerdictAllow, "", rule, out.InputHash)

		if _, ok := v.policy.AllowedResponseModes[cb.ResponseMode]; !ok {
			emit(StageResponseMode, "response_mode", false, VerdictDeny,
				"response_mode.disallowed", "mode="+cb.ResponseMode, out.InputHash)
			return deny(StageResponseMode, "response_mode.disallowed",
				"response_mode not permitted")
		}
		emit(StageResponseMode, "response_mode", true, VerdictAllow,
			"", "mode="+cb.ResponseMode, out.InputHash)

		if cb.TokenHash == "" {
			emit(StageSignature, "token_hash", false, VerdictDeny,
				"token_hash.missing", "v2 callback requires token_hash", out.InputHash)
			return deny(StageSignature, "token_hash.missing", "missing token_hash")
		}
		emit(StageSignature, "token_hash", true, VerdictAllow,
			"", "token_hash present", out.InputHash)
	}

	// 6. 通过：权限判断为允许换码。
	emit(StagePermission, "exchange_decision", true, VerdictAllow,
		"", "all gates passed; token exchange permitted", out.InputHash)
	out.TriggerPoint = StagePermission
	out.Decision = Decision{
		Verdict:     VerdictAllow,
		Stage:       StagePermission,
		ReasonCode:  "allow.all_checks_passed",
		ReasonHuman: "callback accepted for token exchange",
	}
	out.PermissionLog = "rule.allow.all_checks_passed"
	return out
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashExport 暴露证据哈希能力，供证据层复用，避免算法分叉。
func HashExport(b []byte) string { return hashBytes(b) }

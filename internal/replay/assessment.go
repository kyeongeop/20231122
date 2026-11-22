package replay

import (
	"fmt"

	"seedreview/internal/model"
)

func buildAssessment(
	recovery model.Recovery,
	execution execution,
	trace model.Trace,
	traceErr error,
) ([]model.Finding, []model.ManualCheck, string) {
	var findings []model.Finding
	var checks []model.ManualCheck
	conclusion := "inconclusive"

	if execution.status != "ok" {
		severity := "high"
		if execution.status == "timeout" {
			severity = "medium"
		}
		findings = append(findings, model.Finding{
			Code: "REPLAY_FAILED", Severity: severity,
			Title: "恢复后重放未完成",
			Details: map[string]any{
				"status": execution.status, "failure_code": execution.failureCode,
				"message": execution.failureMsg, "signal": execution.signal,
				"exit_code": execution.exitCode,
			},
		})
		checks = append(checks, pendingCheck(
			"REPLAY_FAILURE_TRIAGE",
			"是否已按失败后续操作定位并复现重放故障？",
			true,
		))
		conclusion = "replay_failed"
	}
	if traceErr != nil || len(trace.Starts) == 0 {
		if execution.failureCode == "" {
			findings = append(findings, model.Finding{
				Code: "TRACE_INCOMPLETE", Severity: "medium",
				Title:   "重放 trace 缺失或不完整",
				Details: map[string]any{"error": errorText(traceErr)},
			})
			conclusion = "trace_incomplete"
		}
		checks = append(checks, pendingCheck(
			"TRACE_CAPTURE_CONFIRMED",
			"是否确认目标二进制会写入 SEED_AUDIT_TRACE，并保留完整 NDJSON？",
			true,
		))
	}

	unknownCount := 0
	bypassCount := 0
	for _, start := range trace.Starts {
		if !start.KnownExtension {
			unknownCount++
			findings = append(findings, model.Finding{
				Code: "UNKNOWN_EXTENSION", Severity: "medium",
				Title: "重放记录到未知扩展",
				Details: map[string]any{
					"extension": start.Extension,
					"principal": start.Principal,
					"action":    start.Action,
				},
			})
		}
	}
	for _, permission := range trace.Permissions {
		expected := permission.Expected
		if expected == "" {
			expected = "deny"
		}
		if permission.Actual != expected {
			bypassCount++
			findings = append(findings, model.Finding{
				Code: "PERMISSION_MISMATCH", Severity: "critical",
				Title: "权限判断与预期不一致",
				Details: map[string]any{
					"extension": permission.Extension,
					"expected":  expected, "actual": permission.Actual,
					"policy": permission.Policy, "reason": permission.Reason,
				},
			})
		}
	}
	if unknownCount > 0 && bypassCount == 0 && execution.status == "ok" && traceErr == nil {
		conclusion = "unknown_extension_denied"
	}
	if bypassCount > 0 {
		conclusion = "permission_bypass_suspected"
	}

	restoredSeed := firstNonEmpty(recovery.RecoveredSeed, recovery.Seed)
	if restoredSeed == "0" {
		findings = append(findings, model.Finding{
			Code: "ZERO_SEED_AFTER_RECOVERY", Severity: "high",
			Title: "恢复后随机数种子为零",
			Details: map[string]any{
				"algorithm":      recovery.RNGAlgorithm,
				"recovered_seed": restoredSeed,
				"effective_seed": traceEffectiveSeed(trace, restoredSeed),
				"state_sha256":   recovery.StateSHA256,
			},
		})
	}
	if unknownCount == 0 && execution.status == "ok" && traceErr == nil {
		conclusion = "no_unknown_extension"
	}

	checks = append(checks,
		pendingCheck(
			"UNKNOWN_EXTENSION_PROVENANCE",
			"未知扩展是否来自可信发布源，是否应加入显式允许清单？",
			true,
		),
		pendingCheck(
			"PERMISSION_POLICY_EXPECTATION",
			"权限日志中的 expected/actual 是否与当前安全策略一致？",
			true,
		),
		pendingCheck(
			"KEY_LOG_RETENTION",
			"权限决策和触发位置日志是否已进入集中日志并满足保留期限？",
			true,
		),
		pendingCheck(
			"INDEPENDENT_REPLAY",
			"是否由第二人用同一目标与证据独立重放一次并比对 trace 哈希？",
			true,
		),
	)
	return findings, checks, conclusion
}

func pendingCheck(code, question string, required bool) model.ManualCheck {
	return model.ManualCheck{
		Code: code, Question: question, Required: required, Status: "pending",
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}

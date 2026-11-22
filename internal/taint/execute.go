package taint

import (
	"fmt"
	"strings"

	"taintlab/internal/model"
)

func executeScenario(scenario model.Scenario, raw []byte, diagnostics diagnosticList) model.Result {
	result := baseResult(raw)
	if scenario.CaseID != "" {
		result.CaseID = scenario.CaseID
	}
	if scenario.TraceID != "" {
		result.TraceID = scenario.TraceID
	}
	result.Input.State = "accepted"
	result.Attack = model.AttackInput{
		Source:     scenario.Source,
		Operations: append([]model.Operation(nil), scenario.Operations...),
		Boundary:   scenario.Boundary,
		Permission: scenario.Permission,
		Clocks:     scenario.Clocks,
		TaintPath:  []model.TaintStep{},
	}

	value := scenario.Source.Value
	tainted := scenario.Source.Tainted
	for index, operation := range scenario.Operations {
		kind := strings.ToLower(strings.TrimSpace(operation.Kind))
		seq := operation.Seq
		if seq <= 0 {
			seq = index + 1
			diagnostics.add("info", "assigned_operation_seq",
				fmt.Sprintf("operation %d had no positive seq; using %d", index, seq))
		}
		after, wrapped, err := applyOperation(value, kind, operation.Operand, operation.WidthBits)
		if err != nil {
			diagnostics.add("high", "invalid_operation", fmt.Sprintf(
				"operation seq=%d kind=%q: %s", seq, kind, err.Error()))
			after = value
			wrapped = false
		}
		step := model.TaintStep{
			Ordinal:   index + 1,
			Seq:       seq,
			Kind:      kind,
			Operand:   operation.Operand,
			WidthBits: operation.WidthBits,
			Before:    value,
			After:     after,
			Tainted:   tainted,
			Changed:   after != value,
			Wrapped:   wrapped,
			Location:  operationLocation(kind),
		}
		if wrapped {
			diagnostics.add("warning", "arithmetic_wrap", fmt.Sprintf(
				"seq=%d kind=%s wrapped the signed 64-bit arithmetic value", seq, kind))
		}
		if kind == "trunc" && err == nil && tainted && !result.Trigger.Detected &&
			isNarrowingWidth(operation.WidthBits) {
			result.Trigger = model.Trigger{
				Detected:        true,
				OperationSeq:    seq,
				Location:        operationLocation(kind),
				Reason:          truncationReason(value, after, scenario.Boundary),
				Before:          value,
				After:           after,
				WidthBits:       operation.WidthBits,
				BoundaryCrossed: outsideBoundary(value, scenario.Boundary),
				SourceLabel:     scenario.Source.Label,
			}
		}
		result.Attack.TaintPath = append(result.Attack.TaintPath, step)
		value = after
	}

	result.Permission = evaluatePermission(scenario, result.Trigger, value, tainted)
	if result.Permission.Mismatch {
		diagnostics.add("high", "permission_decision_mismatch", fmt.Sprintf(
			"baseline=%s effective=%s; the effective decision uses the truncated value",
			result.Permission.BaselineDecision, result.Permission.EffectiveDecision))
	}
	if result.Permission.TaintedEscalation {
		diagnostics.add("critical", "tainted_privilege_escalation",
			"tainted truncation changed a denied baseline decision into an allowed effective decision")
	}
	result.Evidence, diagnostics = buildEvidence(result, scenario, diagnostics)
	result.Diagnostics = diagnostics.items
	return result
}

func evaluatePermission(
	scenario model.Scenario,
	trigger model.Trigger,
	effectiveValue int64,
	tainted bool,
) model.PermissionResult {
	policy := strings.TrimSpace(scenario.Permission.Policy)
	if policy == "" {
		policy = "exact_effective_token"
	}
	checkValue := effectiveValue
	if trigger.Detected {
		checkValue = trigger.Before
	}
	baselineAllowed := checkValue == scenario.Permission.RequiredToken
	effectiveAllowed := effectiveValue == scenario.Permission.RequiredToken
	result := model.PermissionResult{
		Evaluated:         true,
		Policy:            policy,
		RequiredToken:     scenario.Permission.RequiredToken,
		CheckValue:        checkValue,
		EffectiveValue:    effectiveValue,
		BaselineDecision:  decision(baselineAllowed),
		EffectiveDecision: decision(effectiveAllowed),
		Decision:          decision(effectiveAllowed),
		Mismatch:          baselineAllowed != effectiveAllowed,
		TaintedValue:      tainted,
	}
	result.TaintedEscalation = result.Mismatch && effectiveAllowed && tainted && trigger.Detected
	return result
}

func decision(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func truncationReason(before, after int64, boundary model.Boundary) string {
	reasons := []string{"tainted_integer_truncation"}
	if before != after {
		reasons = append(reasons, "value_changed")
	} else {
		reasons = append(reasons, "value_unchanged")
	}
	if outsideBoundary(before, boundary) {
		reasons = append(reasons, "boundary_overrun")
	}
	return strings.Join(reasons, "+")
}

func outsideBoundary(value int64, boundary model.Boundary) bool {
	return value < boundary.Min || value > boundary.Max
}

func operationLocation(kind string) string {
	switch kind {
	case "trunc":
		return "internal/taint/ops.go:applyTruncation"
	case "add", "sub", "mul", "div", "mod", "and", "or", "xor", "shl", "shr", "neg", "not":
		return "internal/taint/ops.go:applyArithmetic/" + kind
	default:
		return "internal/taint/ops.go:applyUnknown"
	}
}

func isNarrowingWidth(width int) bool {
	return width == 8 || width == 16 || width == 32
}

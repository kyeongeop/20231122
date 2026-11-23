package experiment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"example.com/deserialize-boundary/internal/ledger"
)

type Checker struct {
	Ledger *ledger.Ledger
}

func (c *Checker) EvaluateCore(ctx context.Context) ([]ledger.Check, error) {
	if c.Ledger == nil {
		return nil, fmt.Errorf("ledger is required")
	}
	checks := make([]ledger.Check, 0, 14)
	parserSteps, parserErr := c.Ledger.Steps(ctx, "parser-boundary")
	ascDigest := parserDigest(parserSteps, "wire-order-asc")
	descDigest := parserDigest(parserSteps, "wire-order-desc")
	checks = append(checks, newCheck("parser_order_equivalence", "parser",
		parserErr == nil && ascDigest != "" && ascDigest == descDigest,
		"wire-order-asc and wire-order-desc produce the same canonical digest",
		fmt.Sprintf("asc=%s desc=%s error=%v", emptyDash(ascDigest), emptyDash(descDigest), parserErr),
		"artifacts/evidence/traces/parser-boundary.jsonl",
		"Both frames contain the same records in opposite wire order."))
	checks = append(checks, expectBoundary(parserSteps, "wire-duplicate-id", "invalid:duplicate_id"))
	checks = append(checks, expectBoundary(parserSteps, "wire-truncated", "invalid:truncated_payload"))

	targetRun, targetErr := c.Ledger.Run(ctx, "cancel-target")
	controlRun, controlErr := c.Ledger.Run(ctx, "cancel-control")
	targetCount, _ := c.Ledger.ScalarInt(ctx, `SELECT COUNT(*) FROM records WHERE run_id = ?`, "cancel-target")
	controlCount, _ := c.Ledger.ScalarInt(ctx, `SELECT COUNT(*) FROM records WHERE run_id = ?`, "cancel-control")
	checks = append(checks, newCheck("cancel_target_zero_commits", "cancellation",
		targetErr == nil && targetRun.Status == "cancelled" && targetCount == 0,
		"cancel-target status=cancelled and committed rows=0",
		fmt.Sprintf("status=%s rows=%d error=%v", targetRun.Status, targetCount, targetErr),
		"artifacts/evidence/traces/cancel-target.jsonl",
		"Midpoint cancellation must prevent all staged records from committing."))
	checks = append(checks, newCheck("cancel_control_zero_commits", "cancellation",
		controlErr == nil && controlRun.Status == "cancelled" && controlCount == 0,
		"cancel-control status=cancelled and committed rows=0",
		fmt.Sprintf("status=%s rows=%d error=%v", controlRun.Status, controlCount, controlErr),
		"artifacts/evidence/traces/cancel-control.jsonl",
		"The second cancellation is an isolated control run."))

	targetSteps, _ := c.Ledger.Steps(ctx, "cancel-target")
	controlSteps, _ := c.Ledger.Steps(ctx, "cancel-control")
	midOK := hasMidpointEvidence(targetSteps, 2, 2)
	checks = append(checks, newCheck("cancel_target_midpoint", "cancellation", midOK,
		"cancel step occurs after 2 accepted records and 2 later submits are rejected",
		fmt.Sprintf("midpoint=%t step_outcomes=%s", midOK, summarizeOutcomes(targetSteps)),
		"artifacts/evidence/traces/cancel-target.jsonl",
		"Confirms cancellation happened in the middle, not before or after the workload."))
	pairOK := targetErr == nil && controlErr == nil &&
		targetRun.Status == controlRun.Status &&
		targetRun.StateDigest == controlRun.StateDigest &&
		normalizedTrace(targetSteps) == normalizedTrace(controlSteps) &&
		len(targetSteps) > 0
	checks = append(checks, newCheck("cancel_pair_equivalent", "cancellation", pairOK,
		"target and control cancellation traces have identical outcomes and state",
		fmt.Sprintf("status_equal=%t digest_equal=%t trace_equal=%t",
			targetRun.Status == controlRun.Status,
			targetRun.StateDigest == controlRun.StateDigest,
			normalizedTrace(targetSteps) == normalizedTrace(controlSteps)),
		"artifacts/evidence/traces/cancel-target.jsonl, artifacts/evidence/traces/cancel-control.jsonl",
		"Normalization excludes timestamps and durations only."))

	ascRun, ascErr := c.Ledger.Run(ctx, "order-asc")
	descRun, descErr := c.Ledger.Run(ctx, "order-desc")
	ascRows, _ := c.Ledger.Records(ctx, "order-asc")
	descRows, _ := c.Ledger.Records(ctx, "order-desc")
	orderOK := ascErr == nil && descErr == nil &&
		ascRun.Status == "committed" && descRun.Status == "committed" &&
		len(ascRows) == 4 && len(descRows) == 4 &&
		ascRun.StateDigest == descRun.StateDigest
	checks = append(checks, newCheck("db_order_equivalence", "ordering", orderOK,
		"ascending and descending submission produce the same canonical state",
		fmt.Sprintf("asc_status=%s rows=%d digest=%s desc_status=%s rows=%d digest=%s",
			ascRun.Status, len(ascRows), short(ascRun.StateDigest),
			descRun.Status, len(descRows), short(descRun.StateDigest)),
		"artifacts/evidence/traces/order-asc.jsonl, artifacts/evidence/traces/order-desc.jsonl",
		"Canonical digest sorts records by id before hashing."))

	dupRun, dupErr := c.Ledger.Run(ctx, "duplicate-submit")
	dupRows, _ := c.Ledger.Records(ctx, "duplicate-submit")
	dupSteps, _ := c.Ledger.Steps(ctx, "duplicate-submit")
	dupCount := countOutcome(dupSteps, "duplicate_submission")
	distinct, _ := c.Ledger.ScalarInt(ctx, `SELECT COUNT(DISTINCT record_id) FROM records WHERE run_id = ?`, "duplicate-submit")
	dupOK := dupErr == nil && dupRun.Status == "committed" && dupCount == 1 &&
		len(dupRows) == 4 && distinct == 4
	checks = append(checks, newCheck("duplicate_submission_rejected", "duplication", dupOK,
		"exactly one duplicate is rejected and four distinct rows commit",
		fmt.Sprintf("status=%s duplicate_events=%d rows=%d distinct=%d error=%v",
			dupRun.Status, dupCount, len(dupRows), distinct, dupErr),
		"artifacts/evidence/traces/duplicate-submit.jsonl",
		"Duplicate id 2 must not create a second SQLite row."))

	totalSteps, _ := c.Ledger.ScalarInt(ctx, `SELECT COUNT(*) FROM steps`)
	badSteps, _ := c.Ledger.ScalarInt(ctx, `SELECT COUNT(*) FROM steps
		WHERE input_sha256 = '' OR input_json = '' OR state_before = ''
		OR state_after = '' OR outcome = '' OR result_json = ''`)
	checks = append(checks, newCheck("step_ledger_complete", "evidence", totalSteps > 0 && badSteps == 0,
		"every step has non-empty input JSON, hash, state before/after, outcome, and result",
		fmt.Sprintf("steps=%d incomplete=%d", totalSteps, badSteps),
		"artifacts/evidence/experiment.db#steps",
		"input_hex is populated only when the step carries a wire frame."))

	for _, check := range checks {
		if err := c.Ledger.PutCheck(ctx, check); err != nil {
			return checks, err
		}
	}
	return checks, nil
}

func parserDigest(steps []ledger.Step, label string) string {
	for _, step := range steps {
		result := resultMap(step)
		if fmt.Sprint(result["label"]) != label {
			continue
		}
		value, _ := result["digest"].(string)
		return value
	}
	return ""
}

func expectBoundary(steps []ledger.Step, label, classification string) ledger.Check {
	for _, step := range steps {
		result := resultMap(step)
		if fmt.Sprint(result["label"]) == label {
			passed := step.Outcome == "boundary_match" && fmt.Sprint(result["classification"]) == classification
			return newCheck("parser_"+strings.ReplaceAll(classification, ":", "_"), "parser", passed,
				label+" classification="+classification,
				fmt.Sprintf("outcome=%s classification=%s", step.Outcome, result["classification"]),
				"artifacts/evidence/traces/parser-boundary.jsonl",
				"Malformed frames must return a typed boundary error.")
		}
	}
	return newCheck("parser_"+strings.ReplaceAll(classification, ":", "_"), "parser", false,
		label+" classification="+classification, "step not found",
		"artifacts/evidence/traces/parser-boundary.jsonl", "Missing parser evidence.")
}

func hasMidpointEvidence(steps []ledger.Step, acceptedBefore, rejectedAfter int) bool {
	cancelResult := map[string]any{}
	rejected := 0
	seenCancel := false
	for _, step := range steps {
		switch step.Outcome {
		case "cancelled":
			seenCancel = true
			cancelResult = resultMap(step)
		case "rejected_after_cancel":
			if seenCancel {
				rejected++
			}
		}
	}
	return seenCancel &&
		toInt(cancelResult["accepted_before_cancel"]) == acceptedBefore &&
		toInt(cancelResult["committed_before_cancel"]) == 0 &&
		rejected == rejectedAfter
}

func normalizedTrace(steps []ledger.Step) string {
	var parts []string
	for _, step := range steps {
		parts = append(parts, step.Action+"|"+step.Outcome+"|"+step.StateAfter)
	}
	return strings.Join(parts, "\n")
}

func summarizeOutcomes(steps []ledger.Step) string {
	counts := make(map[string]int)
	for _, step := range steps {
		counts[step.Outcome]++
	}
	data, _ := json.Marshal(counts)
	return string(data)
}

func countOutcome(steps []ledger.Step, outcome string) int {
	count := 0
	for _, step := range steps {
		if step.Outcome == outcome {
			count++
		}
	}
	return count
}

func resultMap(step ledger.Step) map[string]any {
	out := make(map[string]any)
	_ = json.Unmarshal([]byte(step.ResultJSON), &out)
	return out
}

func toInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return -1
	}
}

func newCheck(id, category string, passed bool, expected, observed, evidence, detail string) ledger.Check {
	return ledger.Check{
		ID:       id,
		Category: category,
		Passed:   passed,
		Expected: expected,
		Observed: observed,
		Evidence: evidence,
		Detail:   detail,
	}
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

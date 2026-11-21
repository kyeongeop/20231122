package experiment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"pathaliaslab/internal/ledger"
	"pathaliaslab/internal/model"
)

type StepOutcome struct {
	Input          []byte
	StateBefore    []byte
	ResultJSON     []byte
	StateAfter     []byte
	Result         model.Result
	EvidenceSHA256 string
}

type RunOutcome struct {
	Scenario         Scenario
	RunID            string
	Steps            []StepOutcome
	FinalState       []byte
	StateDigest      string
	ResolutionDigest string
	EventSHA256      string
	Checks           []ledger.CheckRecord
	Passed           bool
}

func Run(l *ledger.Ledger, scenario Scenario, runID string) (RunOutcome, error) {
	scenarioJSON, err := ScenarioJSON(scenario)
	if err != nil {
		return RunOutcome{}, err
	}
	if err := l.BeginRun(runID, scenario.Name, scenario.Role, scenarioJSON); err != nil {
		return RunOutcome{}, err
	}

	engine := model.NewEngine()
	out := RunOutcome{Scenario: scenario, RunID: runID}
	invariantProblems := make([]string, 0)
	eventHash := ""
	for index, op := range scenario.Steps {
		stepNo := index + 1
		before := engine.StateJSON()
		result := engine.Apply(op)
		after := engine.StateJSON()
		input, err := json.Marshal(op)
		if err != nil {
			return out, err
		}
		resultJSON, err := json.Marshal(result)
		if err != nil {
			return out, err
		}
		eventHash, err = l.AddStep(runID, stepNo, input, before, resultJSON, after)
		if err != nil {
			return out, err
		}
		out.Steps = append(out.Steps, StepOutcome{
			Input: input, StateBefore: before, ResultJSON: resultJSON,
			StateAfter: after, Result: result, EvidenceSHA256: eventHash,
		})
		for _, problem := range engine.Validate() {
			invariantProblems = append(invariantProblems, fmt.Sprintf("step %d: %s", stepNo, problem))
		}
	}

	out.FinalState = engine.StateJSON()
	out.StateDigest = model.Digest(out.FinalState)
	out.ResolutionDigest = engine.ResolutionDigest()
	out.EventSHA256 = eventHash
	if err := l.FinishRun(runID, "running", out.FinalState, out.ResolutionDigest, eventHash, len(scenario.Steps)); err != nil {
		return out, err
	}

	out.Checks, err = evaluateRun(l, scenario, out, engine, invariantProblems)
	if err != nil {
		return out, err
	}
	out.Passed = true
	for _, check := range out.Checks {
		if !check.Passed {
			out.Passed = false
		}
	}
	status := "passed"
	if !out.Passed {
		status = "failed"
	}
	if err := l.SetRunStatus(runID, status); err != nil {
		return out, err
	}
	return out, nil
}

func evaluateRun(l *ledger.Ledger, scenario Scenario, out RunOutcome, engine *model.Engine, invariantProblems []string) ([]ledger.CheckRecord, error) {
	checks := make([]ledger.CheckRecord, 0)
	add := func(name, scope string, expected, actual string, passed bool, detail string) error {
		record := ledger.CheckRecord{
			RunID: out.RunID, CheckName: name, Scope: scope,
			Expected: expected, Actual: actual, Passed: passed, Detail: detail,
		}
		if err := l.AddCheck(record); err != nil {
			return err
		}
		checks = append(checks, record)
		return nil
	}
	stepNumbers := func(outcome string) []int {
		numbers := make([]int, 0)
		for index, step := range out.Steps {
			if step.Result.Outcome == outcome {
				numbers = append(numbers, index+1)
			}
		}
		return numbers
	}
	if err := add(
		"conflict_steps_match", "scenario",
		jsonString(scenario.Expect.ConflictSteps), jsonString(stepNumbers("conflict")),
		equalInts(scenario.Expect.ConflictSteps, stepNumbers("conflict")),
		"conflict is expected only at the designated mid-run steps",
	); err != nil {
		return nil, err
	}
	if err := add(
		"cancel_steps_match", "scenario",
		jsonString(scenario.Expect.CancelSteps), jsonString(stepNumbers("canceled")),
		equalInts(scenario.Expect.CancelSteps, stepNumbers("canceled")),
		"one effective cancellation is expected in the scenario",
	); err != nil {
		return nil, err
	}
	if err := add(
		"duplicate_steps_noop", "scenario",
		jsonString(scenario.Expect.DuplicateNoopSteps), jsonString(stepNumbers("duplicate_noop")),
		equalInts(scenario.Expect.DuplicateNoopSteps, stepNumbers("duplicate_noop")),
		"exact operation replays must not mutate state",
	); err != nil {
		return nil, err
	}

	aliases := make(map[string]model.AliasView)
	conflicted := make([]string, 0)
	state := engine.Snapshot()
	for _, alias := range state.Aliases {
		aliases[alias.Alias] = alias
		if alias.Status == "conflicted" {
			conflicted = append(conflicted, alias.Alias)
		}
	}
	alias, found := aliases[scenario.Expect.FinalAlias]
	finalActual := "not-found"
	if found {
		target := "none"
		if len(alias.Targets) == 1 {
			target = alias.Targets[0]
		}
		finalActual = alias.Status + ":" + target
	}
	finalExpected := "active:" + scenario.Expect.FinalTarget
	if scenario.Expect.ConflictFree {
		if err := add(
			"final_conflict_free", "state",
			"no conflicted aliases", jsonString(conflicted), len(conflicted) == 0,
			"the designated cancellation must remove the conflict",
		); err != nil {
			return nil, err
		}
	}
	if err := add(
		"final_resolution", "state", finalExpected, finalActual, finalActual == finalExpected,
		"final alias must resolve to the surviving target",
	); err != nil {
		return nil, err
	}
	sort.Strings(invariantProblems)
	if err := add(
		"state_invariants", "state",
		"no invariant violations", jsonString(invariantProblems), len(invariantProblems) == 0,
		"every post-step snapshot must be internally consistent",
	); err != nil {
		return nil, err
	}
	chainErr := l.VerifyEvidenceChain(out.RunID)
	chainDetail := "hash chain verified"
	if chainErr != nil {
		chainDetail = chainErr.Error()
	}
	if err := add(
		"evidence_chain", "evidence",
		"valid chain", chainDetail, chainErr == nil,
		"input, before-state, result, and after-state are chained per step",
	); err != nil {
		return nil, err
	}
	if err := add(
		"step_count", "scenario",
		fmt.Sprintf("%d", len(scenario.Steps)), fmt.Sprintf("%d", len(out.Steps)),
		len(scenario.Steps) == len(out.Steps), "all scenario input steps were persisted",
	); err != nil {
		return nil, err
	}
	return checks, nil
}

func jsonString(value any) string {
	data, _ := json.Marshal(value)
	if string(data) == "null" {
		return "[]"
	}
	return string(data)
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func Replay(l *ledger.Ledger, sourceRunID, replayRunID string) (RunOutcome, ledger.ReplayRecord, error) {
	source, err := l.Run(sourceRunID)
	if err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	scenario, err := DecodeScenario([]byte(source.ScenarioJSON))
	if err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	replayed, err := Run(l, scenario, replayRunID)
	if err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	sourceSteps, err := l.Steps(sourceRunID)
	if err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}

	record := ledger.ReplayRecord{
		SourceRunID: sourceRunID, ReplayRunID: replayRunID,
		InputMatch: true, StateMatch: true, ResultMatch: true, Passed: true,
	}
	if len(sourceSteps) != len(replayed.Steps) {
		record.Passed = false
		record.Detail = fmt.Sprintf("step count differs: source=%d replay=%d", len(sourceSteps), len(replayed.Steps))
	} else {
		mismatches := make([]string, 0)
		for index, step := range sourceSteps {
			actual := replayed.Steps[index]
			if !bytes.Equal([]byte(step.InputJSON), actual.Input) {
				record.InputMatch = false
				mismatches = append(mismatches, fmt.Sprintf("step %d input", step.StepNo))
			}
			if !bytes.Equal([]byte(step.ResultJSON), actual.ResultJSON) {
				record.ResultMatch = false
				mismatches = append(mismatches, fmt.Sprintf("step %d result", step.StepNo))
			}
			if !bytes.Equal([]byte(step.StateBeforeJSON), actual.StateBefore) ||
				!bytes.Equal([]byte(step.StateAfterJSON), actual.StateAfter) {
				record.StateMatch = false
				mismatches = append(mismatches, fmt.Sprintf("step %d state", step.StepNo))
			}
		}
		if model.Digest(replayed.FinalState) != source.FinalStateSHA256 {
			record.StateMatch = false
			mismatches = append(mismatches, "final state")
		}
		record.Passed = len(mismatches) == 0
		if record.Passed {
			record.Detail = "all inputs, results, and states reproduced byte-for-byte"
		} else {
			record.Detail = "mismatches: " + joinStrings(mismatches, ", ")
		}
	}
	if !replayed.Passed {
		record.Passed = false
		record.Detail = joinStrings([]string{record.Detail, "replay run checks failed"}, "; ")
	}
	if err := l.AddCheck(ledger.CheckRecord{
		RunID: replayRunID, CheckName: "replay_trace_match", Scope: "replay",
		Expected: "byte-identical inputs/results/states",
		Actual:   record.Detail,
		Passed:   record.Passed, Detail: record.Detail,
	}); err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	status := "passed"
	if !record.Passed {
		status = "failed"
		replayed.Passed = false
	}
	if err := l.SetRunStatus(replayRunID, status); err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	if err := l.AddReplay(record); err != nil {
		return RunOutcome{}, ledger.ReplayRecord{}, err
	}
	return replayed, record, nil
}

func ExecuteAll(l *ledger.Ledger) ([]RunOutcome, []ledger.CheckRecord, error) {
	scenarios, err := Scenarios()
	if err != nil {
		return nil, nil, err
	}
	byName := make(map[string]RunOutcome)
	runs := make([]RunOutcome, 0, len(scenarios)+1)
	for _, scenario := range scenarios {
		out, err := Run(l, scenario, scenario.Name)
		if err != nil {
			return nil, nil, err
		}
		byName[scenario.Name] = out
		runs = append(runs, out)
	}
	replayed, record, err := Replay(l, "primary_cancel", "primary_cancel-replay")
	if err != nil {
		return nil, nil, err
	}
	runs = append(runs, replayed)

	primary := byName["primary_cancel"]
	control := byName["control_cancel"]
	order := byName["order_swap"]
	duplicate := byName["duplicate_probe"]
	global := make([]ledger.CheckRecord, 0)
	addGlobal := func(name, expected, actual string, passed bool, detail string) error {
		check := ledger.CheckRecord{
			RunID: "global", CheckName: name, Scope: "cross-run",
			Expected: expected, Actual: actual, Passed: passed, Detail: detail,
		}
		if err := l.AddCheck(check); err != nil {
			return err
		}
		global = append(global, check)
		return nil
	}
	if err := addGlobal(
		"control_has_no_conflict", "no conflict outcome",
		fmt.Sprintf("%d conflict outcomes", countOutcome(control, "conflict")),
		countOutcome(control, "conflict") == 0,
		"same cancellation timing without alias collision is the control",
	); err != nil {
		return nil, nil, err
	}
	if err := addGlobal(
		"same_cancel_position", fmt.Sprintf("primary=%d control=%d", primary.Scenario.CancelAtStep, control.Scenario.CancelAtStep),
		fmt.Sprintf("primary=%d control=%d", primary.Scenario.CancelAtStep, control.Scenario.CancelAtStep),
		primary.Scenario.CancelAtStep == control.Scenario.CancelAtStep,
		"both runs cancel at the same ordinal step",
	); err != nil {
		return nil, nil, err
	}
	if err := addGlobal(
		"order_resolution_matches_primary", primary.ResolutionDigest, order.ResolutionDigest,
		primary.ResolutionDigest == order.ResolutionDigest,
		"reversing conflicting submissions converges after id-addressed cancellation",
	); err != nil {
		return nil, nil, err
	}
	if err := addGlobal(
		"duplicate_resolution_matches_primary", primary.ResolutionDigest, duplicate.ResolutionDigest,
		primary.ResolutionDigest == duplicate.ResolutionDigest,
		"exact duplicate submissions and cancellations do not change the resolution",
	); err != nil {
		return nil, nil, err
	}
	unchanged, duplicateSteps := duplicateStepsUnchanged(duplicate)
	if err := addGlobal(
		"duplicate_steps_state_unchanged", "all duplicate noop steps keep state",
		fmt.Sprintf("%d/%d unchanged", unchanged, duplicateSteps),
		unchanged == duplicateSteps,
		"state-before and state-after hashes are identical at every duplicate step",
	); err != nil {
		return nil, nil, err
	}
	if err := addGlobal(
		"replay_matches_source", "byte-identical replay", record.Detail,
		record.Passed, "primary scenario is replayed from the scenario JSON stored in SQLite",
	); err != nil {
		return nil, nil, err
	}

	allPassed := record.Passed
	for _, run := range runs {
		if !run.Passed {
			allPassed = false
		}
	}
	for _, check := range global {
		if !check.Passed {
			allPassed = false
		}
	}
	if err := addGlobal(
		"all_automatic_checks_pass", "true", fmt.Sprintf("%t", allPassed), allPassed,
		"aggregate of scenario, replay, and cross-run checks",
	); err != nil {
		return nil, nil, err
	}
	return runs, global, nil
}

func countOutcome(out RunOutcome, outcome string) int {
	count := 0
	for _, step := range out.Steps {
		if step.Result.Outcome == outcome {
			count++
		}
	}
	return count
}

func duplicateStepsUnchanged(out RunOutcome) (int, int) {
	unchanged, total := 0, 0
	for _, step := range out.Steps {
		if step.Result.Outcome != "duplicate_noop" {
			continue
		}
		total++
		if bytes.Equal(step.StateBefore, step.StateAfter) {
			unchanged++
		}
	}
	return unchanged, total
}

func joinStrings(values []string, separator string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += separator
		}
		result += value
	}
	return result
}

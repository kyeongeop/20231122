package experiment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"depthlab/internal/graphql"
	"depthlab/internal/store"
)

type replayOutcome struct {
	Integrity     *store.Violation
	SubjectFirst  *graphql.Failure
	ReplayedSteps int
	AnalyzedQuery string
}

func runChecks(s *store.Store, limit int, truncated, recovered []store.StoredStep) ([]CheckView, error) {
	var checks []CheckView
	truncatedReplay := replaySteps(TruncatedRunID, truncated, limit)
	truncatedCheck, err := normalReplayCheck(
		"check_truncated_replay", "replay_truncated", TruncatedRunID, truncatedReplay,
	)
	if err != nil {
		return nil, err
	}
	checks = append(checks, truncatedCheck)

	recoveredReplay := replaySteps(RecoveredRunID, recovered, limit)
	recoveredCheck, err := normalReplayCheck(
		"check_recovered_replay", "replay_recovered_control", RecoveredRunID, recoveredReplay,
	)
	if err != nil {
		return nil, err
	}
	checks = append(checks, recoveredCheck)

	orderCheck, err := orderChangeCheck(truncated, limit)
	if err != nil {
		return nil, err
	}
	checks = append(checks, orderCheck)

	duplicateCheck, err := duplicateSubmissionCheck(s, truncated)
	if err != nil {
		return nil, err
	}
	checks = append(checks, duplicateCheck)

	for _, check := range checks {
		stored := store.Check{
			CheckID: check.CheckID, Kind: check.Kind, SourceRunID: TruncatedRunID,
			Status: check.Status, ObservedJSON: check.Observed,
		}
		if check.FirstError != nil {
			stored.FirstErrorSeq = check.FirstError.Seq
			stored.FirstErrorStage = check.FirstError.Stage
			stored.FirstErrorCode = check.FirstError.Code
			stored.FirstErrorDetail = check.FirstError.Detail
		}
		if check.CheckID == "check_recovered_replay" {
			stored.SourceRunID = RecoveredRunID
		}
		if err := s.InsertCheck(stored); err != nil {
			return nil, err
		}
	}
	return checks, nil
}

func replaySteps(runID string, steps []store.StoredStep, limit int) replayOutcome {
	if violation := store.VerifyChain(runID, steps); violation != nil {
		return replayOutcome{Integrity: violation}
	}
	var subjectFirst *graphql.Failure
	var analyzedQuery string
	for i, stored := range steps {
		query, err := queryFromInput(stored.Step.Input)
		if err != nil {
			return replayOutcome{
				Integrity: &store.Violation{
					Seq: stored.Step.Seq, Stage: stored.Step.Stage,
					Code: "REPLAY_INPUT", Detail: err.Error(),
				},
				ReplayedSteps: i, AnalyzedQuery: analyzedQuery,
			}
		}
		if i == 0 {
			analyzedQuery = query
		}
		trace := graphql.Analyze(query, limit)
		if stored.Step.Seq < 1 || stored.Step.Seq > len(trace.Steps) {
			return replayOutcome{
				Integrity: &store.Violation{
					Seq: stored.Step.Seq, Stage: stored.Step.Stage,
					Code:   "REPLAY_SEQUENCE",
					Detail: fmt.Sprintf("seq %d has no matching analysis step", stored.Step.Seq),
				},
				ReplayedSteps: i, AnalyzedQuery: analyzedQuery,
			}
		}
		fresh := trace.Steps[stored.Step.Seq-1]
		if mismatch := compareStep(fresh, stored.Step); mismatch != "" {
			return replayOutcome{
				Integrity: &store.Violation{
					Seq: stored.Step.Seq, Stage: stored.Step.Stage,
					Code: "REPLAY_MISMATCH", Detail: mismatch,
				},
				ReplayedSteps: i, AnalyzedQuery: analyzedQuery,
			}
		}
		subjectFirst = trace.FirstError
	}
	return replayOutcome{
		SubjectFirst: subjectFirst, ReplayedSteps: len(steps), AnalyzedQuery: analyzedQuery,
	}
}

func normalReplayCheck(checkID, kind, runID string, outcome replayOutcome) (CheckView, error) {
	observed := map[string]any{
		"replay_integrity":   "pass",
		"replayed_steps":     outcome.ReplayedSteps,
		"source_run_id":      runID,
		"source_first_error": outcome.SubjectFirst,
	}
	status := "pass"
	var first *ErrorView
	if outcome.Integrity != nil {
		status = "fail"
		first = storeFailureView(outcome.Integrity)
		observed["replay_integrity"] = "fail"
		observed["integrity_error"] = first
	} else if outcome.SubjectFirst != nil {
		first = failureView(outcome.SubjectFirst)
	}
	body, err := json.Marshal(observed)
	if err != nil {
		return CheckView{}, err
	}
	return CheckView{
		CheckID: checkID, Kind: kind, Status: status, FirstError: first, Observed: body,
	}, nil
}

func orderChangeCheck(steps []store.StoredStep, limit int) (CheckView, error) {
	if len(steps) < 3 {
		return CheckView{}, fmt.Errorf("need at least 3 steps for order-change check")
	}
	variant := append([]store.StoredStep(nil), steps...)
	variant[1], variant[2] = variant[2], variant[1]
	outcome := replaySteps(TruncatedRunID, variant, limit)
	if outcome.Integrity == nil {
		return CheckView{}, fmt.Errorf("reordered replay unexpectedly passed")
	}

	first := storeFailureView(outcome.Integrity)
	first.Stage = "replay_order"
	first.Position = 2
	first.ExpectedSeq = 2
	first.ObservedSeq = variant[1].Step.Seq

	offending := variant[1]
	observed := map[string]any{
		"original_order": []int{1, 2, 3, 4, 5},
		"replay_order":   []int{1, 3, 2, 4, 5},
		"first_error":    first,
		"offending_step": map[string]any{
			"seq": offending.Step.Seq, "stage": offending.Step.Stage,
			"input": offending.Step.Input, "state_before": offending.Step.StateBefore,
			"state_after": offending.Step.StateAfter, "result": offending.Step.Result,
			"status": offending.Step.Status, "error_code": offending.Step.ErrorCode,
			"prev_hash": offending.PrevHash, "entry_hash": offending.EntryHash,
		},
	}
	body, err := json.Marshal(observed)
	if err != nil {
		return CheckView{}, err
	}
	status := "fail"
	if outcome.Integrity.Code == "STEP_OUT_OF_ORDER" &&
		first.ExpectedSeq == 2 && first.ObservedSeq == 3 {
		status = "pass"
	}
	return CheckView{
		CheckID: "check_order_changed", Kind: "order_changed_replay",
		Status: status, FirstError: first, Observed: body,
	}, nil
}

func duplicateSubmissionCheck(s *store.Store, steps []store.StoredStep) (CheckView, error) {
	if len(steps) < 2 {
		return CheckView{}, fmt.Errorf("need at least 2 steps for duplicate check")
	}
	duplicate := steps[1]
	_, err := s.SubmitStep(TruncatedRunID, duplicate.Step, "duplicate-submit-probe")
	if err == nil {
		return CheckView{}, fmt.Errorf("duplicate submission unexpectedly accepted")
	}
	var violation *store.Violation
	if !errors.As(err, &violation) {
		return CheckView{}, err
	}
	first := storeFailureView(violation)
	first.Stage = "submission"
	observed := map[string]any{
		"submitted_step": map[string]any{
			"seq": duplicate.Step.Seq, "stage": duplicate.Step.Stage,
			"input": duplicate.Step.Input, "state_before": duplicate.Step.StateBefore,
			"state_after": duplicate.Step.StateAfter, "result": duplicate.Step.Result,
			"status": duplicate.Step.Status, "entry_hash": duplicate.EntryHash,
		},
		"decision":    "rejected",
		"first_error": first,
	}
	body, marshalErr := json.Marshal(observed)
	if marshalErr != nil {
		return CheckView{}, marshalErr
	}
	status := "fail"
	if violation.Code == "DUPLICATE_STEP" && violation.Seq == 2 {
		status = "pass"
	}
	return CheckView{
		CheckID: "check_duplicate_submission", Kind: "duplicate_submission",
		Status: status, FirstError: first, Observed: body,
	}, nil
}

func queryFromInput(raw json.RawMessage) (string, error) {
	var input struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		return "", fmt.Errorf("decode step input: %w", err)
	}
	return input.Query, nil
}

func compareStep(fresh, stored graphql.Step) string {
	if !bytes.Equal(fresh.Input, stored.Input) {
		return "step input differs from fresh analysis"
	}
	if !bytes.Equal(fresh.StateBefore, stored.StateBefore) {
		return "state_before differs from fresh analysis"
	}
	if !bytes.Equal(fresh.StateAfter, stored.StateAfter) {
		return "state_after differs from fresh analysis"
	}
	if !bytes.Equal(fresh.Result, stored.Result) {
		return "result differs from fresh analysis"
	}
	if fresh.Status != stored.Status || fresh.ErrorCode != stored.ErrorCode ||
		fresh.ErrorDetail != stored.ErrorDetail {
		return "status/error differs from fresh analysis"
	}
	return ""
}

func storeFailureView(violation *store.Violation) *ErrorView {
	return &ErrorView{Seq: violation.Seq, Stage: violation.Stage, Code: violation.Code, Detail: violation.Detail}
}

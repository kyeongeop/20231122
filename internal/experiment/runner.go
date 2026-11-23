package experiment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"example.com/deserialize-boundary/internal/ledger"
	"example.com/deserialize-boundary/internal/wire"
)

type Runner struct {
	Ledger *ledger.Ledger
	OutDir string
}

func (r *Runner) RunCore(ctx context.Context) ([]ScenarioResult, error) {
	if r.Ledger == nil {
		return nil, errors.New("ledger is required")
	}
	if err := os.MkdirAll(filepath.Join(r.OutDir, "traces"), 0o755); err != nil {
		return nil, err
	}
	var results []ScenarioResult
	for _, scenario := range CoreScenarios() {
		result, err := r.RunScenario(ctx, scenario)
		if err != nil {
			return results, fmt.Errorf("scenario %s: %w", scenario.ID, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (r *Runner) RunScenario(ctx context.Context, scenario Scenario) (ScenarioResult, error) {
	runID := scenario.RunID
	if runID == "" {
		runID = scenario.ID
	}
	if err := r.Ledger.ResetRun(ctx, runID); err != nil {
		return ScenarioResult{}, err
	}
	if err := r.Ledger.StartRun(ctx, ledger.Run{
		ID:       runID,
		Scenario: scenario.ID,
		Role:     scenario.Role,
		Mode:     scenario.Mode,
		Seed:     1,
		Expected: scenario.Expected,
		Status:   "running",
	}); err != nil {
		return ScenarioResult{}, err
	}

	state := State{Phase: "new", LastOutcome: "started"}
	staged := make([]wire.Record, 0, 4)
	stagedSeq := make(map[int]int)
	recorder := &stepRecorder{ctx: ctx, ledger: r.Ledger, runID: runID}
	outcomes := make(map[string]int)
	executionErr := error(nil)

	for index, op := range scenario.Ops {
		before := state.clone()
		recorder.started = time.Now()
		commit := func(records []wire.Record) error {
			return r.commitStaged(ctx, runID, records)
		}
		input, outcome, result, err := applyOp(op, &state, &staged, stagedSeq, index, commit)
		if err != nil {
			outcome = "execution_error"
			result["error"] = err.Error()
			executionErr = err
		}
		state.LastOutcome = outcome
		after := state.clone()
		if recordErr := recorder.record(before, after, op.Kind, outcome, eventInput{
			Scenario: scenario.ID,
			Index:    index,
			Op:       op,
			FrameHex: input,
		}, result); recordErr != nil {
			return ScenarioResult{}, recordErr
		}
		outcomes[outcome]++
		if executionErr != nil {
			break
		}
	}

	records, err := r.Ledger.Records(ctx, runID)
	if err != nil {
		return ScenarioResult{}, err
	}
	recordIDs := make([]int, 0, len(records))
	wireRecords := make([]wire.Record, 0, len(records))
	for _, rec := range records {
		recordIDs = append(recordIDs, rec.ID)
		wireRecords = append(wireRecords, wire.Record{ID: uint16(rec.ID), Payload: rec.Payload})
	}
	digest := wire.CanonicalDigest(wireRecords)
	status := finalStatus(state, executionErr)
	if err := r.Ledger.CompleteRun(ctx, runID, status, digest); err != nil {
		return ScenarioResult{}, err
	}
	if err := r.writeTrace(ctx, runID); err != nil {
		return ScenarioResult{}, err
	}
	return ScenarioResult{
		RunID:       runID,
		Scenario:    scenario.ID,
		Role:        scenario.Role,
		Status:      status,
		StateDigest: digest,
		RecordIDs:   recordIDs,
		Steps:       recorder.seq,
		Outcomes:    outcomes,
	}, executionErr
}

func applyOp(op Op, state *State, staged *[]wire.Record, stagedSeq map[int]int, index int, commit func([]wire.Record) error) (string, string, map[string]any, error) {
	switch op.Kind {
	case OpSubmit:
		return applySubmit(op, state, staged, stagedSeq, index)
	case OpCancel:
		result := map[string]any{
			"reason":                  op.Reason,
			"accepted_before_cancel":  len(*staged),
			"committed_before_cancel": len(state.CommittedIDs),
		}
		if state.Canceled {
			return "", "duplicate_cancel", result, nil
		}
		state.Canceled = true
		state.Phase = "cancelled"
		return "", "cancelled", result, nil
	case OpCommit:
		result := map[string]any{
			"staged_count":  len(*staged),
			"canceled":      state.Canceled,
			"committed_ids": append([]int(nil), state.CommittedIDs...),
		}
		if state.Canceled {
			state.Phase = "cancelled"
			return "", "canceled_no_commit", result, nil
		}
		if err := commit(*staged); err != nil {
			state.Phase = "commit_failed"
			result["error"] = err.Error()
			return "", "commit_failed", result, err
		}
		state.Phase = "committed"
		for _, rec := range *staged {
			state.CommittedIDs = append(state.CommittedIDs, int(rec.ID))
		}
		result["committed_ids"] = append([]int(nil), state.CommittedIDs...)
		result["committed_count"] = len(state.CommittedIDs)
		return "", "committed", result, nil
	case OpParseRaw:
		return applyParseRaw(op, state)
	default:
		return "", "unknown_op", map[string]any{"kind": op.Kind}, fmt.Errorf("unknown operation %q", op.Kind)
	}
}

func (r *Runner) commitStaged(ctx context.Context, runID string, records []wire.Record) error {
	rows := make([]ledger.Record, 0, len(records))
	positions := make(map[uint16]int, len(records))
	for i, rec := range records {
		positions[rec.ID] = i + 1
		rows = append(rows, ledger.Record{
			RunID:          runID,
			ID:             int(rec.ID),
			Payload:        rec.Payload,
			CanonicalSHA:   wire.CanonicalDigest([]wire.Record{rec}),
			SourceSequence: positions[rec.ID],
		})
	}
	return r.Ledger.CommitRecords(ctx, rows)
}

func applySubmit(op Op, state *State, staged *[]wire.Record, stagedSeq map[int]int, index int) (string, string, map[string]any, error) {
	if op.Record == nil {
		return "", "invalid_input", map[string]any{}, errors.New("submit has no record")
	}
	frame, err := wire.Encode(wire.Envelope{Records: []wire.Record{*op.Record}})
	if err != nil {
		return "", "invalid_input", map[string]any{"error": err.Error()}, err
	}
	parsed, err := wire.Parse(frame)
	if err != nil {
		return rawHex(frame), "invalid_frame", map[string]any{
			"classification": wire.Classify(err),
			"error":          err.Error(),
		}, err
	}
	result := map[string]any{
		"record_id":      int(op.Record.ID),
		"frame_bytes":    len(frame),
		"frame_sha":      sha256Hex(frame),
		"classification": "valid",
	}
	if state.Canceled {
		result["accepted"] = false
		result["reason"] = "run_already_cancelled"
		return rawHex(frame), "rejected_after_cancel", result, nil
	}
	for i, rec := range *staged {
		if rec.ID == op.Record.ID {
			first := stagedSeq[int(op.Record.ID)]
			result["accepted"] = false
			result["duplicate_of_index"] = first
			result["existing_staged_position"] = i
			result["duplicate_index"] = index
			return rawHex(frame), "duplicate_submission", result, nil
		}
	}
	*staged = append(*staged, parsed.Records[0])
	stagedSeq[int(op.Record.ID)] = index
	state.StagedIDs = append(state.StagedIDs, int(op.Record.ID))
	state.Phase = "staging"
	result["accepted"] = true
	result["staged_count"] = len(*staged)
	return rawHex(frame), "staged", result, nil
}

func applyParseRaw(op Op, state *State) (string, string, map[string]any, error) {
	data, err := hex.DecodeString(op.RawHex)
	if err != nil {
		return op.RawHex, "invalid_hex", map[string]any{"error": err.Error()}, err
	}
	envelope, parseErr := wire.Parse(data)
	classification := wire.Classify(parseErr)
	result := map[string]any{
		"label":          op.Label,
		"bytes":          len(data),
		"classification": classification,
		"expected":       op.ExpectKind,
	}
	if parseErr != nil {
		result["error"] = parseErr.Error()
	} else {
		digest := wire.CanonicalDigest(envelope.Records)
		result["digest"] = digest
		result["record_ids"] = recordIDs(envelope.Records)
		if state.ParserDigests == nil {
			state.ParserDigests = make(map[string]string)
		}
		state.ParserDigests[op.Label] = digest
	}
	outcome := "boundary_match"
	if classification != op.ExpectKind {
		outcome = "boundary_mismatch"
	}
	state.LastOutcome = outcome
	state.Phase = "parsed"
	return op.RawHex, outcome, result, nil
}

func recordIDs(records []wire.Record) []int {
	out := make([]int, 0, len(records))
	for _, rec := range records {
		out = append(out, int(rec.ID))
	}
	return out
}

func finalStatus(state State, executionErr error) string {
	if executionErr != nil {
		return "failed"
	}
	switch state.Phase {
	case "committed":
		return "committed"
	case "cancelled":
		return "cancelled"
	case "parsed":
		return "complete"
	default:
		return "incomplete"
	}
}

func (r *Runner) writeTrace(ctx context.Context, runID string) error {
	data, err := r.Ledger.ExportJSONL(ctx, runID)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.OutDir, "traces", runID+".jsonl"), data, 0o644)
}

func LoadOpsFromTrace(path string) ([]Op, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ops []Op
	for _, line := range splitLines(data) {
		var step ledger.Step
		if err := json.Unmarshal(line, &step); err != nil {
			return nil, err
		}
		var input eventInput
		if err := json.Unmarshal([]byte(step.InputJSON), &input); err != nil {
			return nil, err
		}
		ops = append(ops, input.Op)
	}
	return ops, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

package experiment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/deserialize-boundary/internal/ledger"
)

type ReplayResult struct {
	SourceRun   string `json:"source_run"`
	ReplayRun   string `json:"replay_run"`
	StatusEqual bool   `json:"status_equal"`
	DigestEqual bool   `json:"digest_equal"`
	StepsEqual  bool   `json:"steps_equal"`
	HashesEqual bool   `json:"input_hashes_equal"`
}

func ReplayCore(ctx context.Context, source, destination *ledger.Ledger, outDir string) ([]ReplayResult, error) {
	if source == nil || destination == nil {
		return nil, fmt.Errorf("source and destination ledgers are required")
	}
	runner := &Runner{Ledger: destination, OutDir: outDir}
	var results []ReplayResult
	var failures []string
	for _, scenario := range CoreScenarios() {
		sourceRun, err := source.Run(ctx, scenario.ID)
		if err != nil {
			return results, fmt.Errorf("read source run %s: %w", scenario.ID, err)
		}
		sourceSteps, err := source.Steps(ctx, scenario.ID)
		if err != nil {
			return results, err
		}
		ops, sourceInputHashes, err := opsFromSteps(sourceSteps)
		if err != nil {
			return results, err
		}
		replayRunID := "replay-" + scenario.ID
		replayScenario := scenario
		replayScenario.RunID = replayRunID
		replayScenario.Ops = ops
		_, runErr := runner.RunScenario(ctx, replayScenario)
		if runErr != nil {
			failures = append(failures, scenario.ID+": "+runErr.Error())
		}
		replayRun, err := destination.Run(ctx, replayRunID)
		if err != nil {
			return results, fmt.Errorf("read destination run %s: %w", replayRunID, err)
		}
		replaySteps, err := destination.Steps(ctx, replayRunID)
		if err != nil {
			return results, err
		}
		_, replayInputHashes, err := opsFromSteps(replaySteps)
		if err != nil {
			return results, err
		}
		sourceRows, _ := source.Records(ctx, scenario.ID)
		replayRows, _ := destination.Records(ctx, replayRunID)
		stepEqual := outcomeTrace(sourceSteps) == outcomeTrace(replaySteps)
		hashesEqual := equalStrings(sourceInputHashes, replayInputHashes)
		result := ReplayResult{
			SourceRun:   scenario.ID,
			ReplayRun:   replayRunID,
			StatusEqual: sourceRun.Status == replayRun.Status,
			DigestEqual: sourceRun.StateDigest == replayRun.StateDigest,
			StepsEqual:  stepEqual,
			HashesEqual: hashesEqual,
		}
		if !result.StatusEqual || !result.DigestEqual || !result.StepsEqual ||
			!result.HashesEqual || len(sourceRows) != len(replayRows) {
			failures = append(failures, scenario.ID)
		}
		results = append(results, result)
	}
	passed := len(failures) == 0
	check := newCheck("replay_core_equivalence", "replay", passed,
		"all core runs rebuild with identical status, digest, step outcomes, and input hashes",
		fmt.Sprintf("runs=%d failures=%s", len(results), strings.Join(failures, ",")),
		"artifacts/evidence/replay.db, artifacts/evidence/traces/replay-*.jsonl",
		"Replay uses only the input_json recorded in each source ledger step.")
	if err := source.PutCheck(ctx, check); err != nil {
		return results, fmt.Errorf("record replay check in source: %w", err)
	}
	if err := destination.PutCheck(ctx, check); err != nil {
		return results, fmt.Errorf("record replay check in destination: %w", err)
	}
	if err := writeReplayReport(outDir, results); err != nil {
		return results, err
	}
	return results, nil
}

func opsFromSteps(steps []ledger.Step) ([]Op, []string, error) {
	var ops []Op
	var hashes []string
	for _, step := range steps {
		if step.Phase != "event" {
			continue
		}
		var input eventInput
		if err := json.Unmarshal([]byte(step.InputJSON), &input); err != nil {
			return nil, nil, err
		}
		ops = append(ops, input.Op)
		hashes = append(hashes, step.InputSHA256)
	}
	return ops, hashes, nil
}

func outcomeTrace(steps []ledger.Step) string {
	var trace []string
	for _, step := range steps {
		if step.Phase != "event" {
			continue
		}
		trace = append(trace, step.Action+"="+step.Outcome)
	}
	return strings.Join(trace, "\n")
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func writeReplayReport(outDir string, results []ReplayResult) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "replay-results.json"), append(data, '\n'), 0o644)
}

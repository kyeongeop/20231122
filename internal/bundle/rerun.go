package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"auditfix/internal/runner"
)

type semanticEvidence struct {
	Verdict         string                  `json:"verdict"`
	Classification  string                  `json:"classification"`
	ChainOK         bool                    `json:"chain_ok"`
	AnchorPairs     int                     `json:"anchor_pairs"`
	ClockOffsetNS   int64                   `json:"clock_offset_ns"`
	Findings        []string                `json:"findings"`
	MissingSegments []runner.MissingSegment `json:"missing_segments"`
	ExitCode        int                     `json:"exit_code"`
	Signal          int                     `json:"signal"`
	TimedOut        bool                    `json:"timed_out"`
}

func rerunSamples(ctx context.Context, root string, loaded loadedBundle,
	options VerifyOptions) ([]RerunResult, error) {
	if options.HarnessPath == "" {
		return nil, fmt.Errorf("--harness is required with --rerun")
	}
	harnessPath := options.HarnessPath
	harnessSHA, _, err := sha256File(harnessPath)
	if err != nil {
		return nil, fmt.Errorf("hash rerun harness: %w", err)
	}
	if harnessSHA != loaded.manifest.HarnessSHA256 {
		return nil, fmt.Errorf("rerun harness hash %s does not match bundle %s",
			harnessSHA, loaded.manifest.HarnessSHA256)
	}
	info, err := os.Stat(harnessPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("rerun harness is not executable")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = time.Duration(loaded.manifest.TimeoutMS) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	latest := make(map[string]AttemptRow)
	for _, attempt := range loaded.attempts {
		if isTerminal(attempt.Status) {
			latest[attempt.SampleID] = attempt
		}
	}
	var results []RerunResult
	for _, sample := range loaded.samples {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		expected, ok := latest[sample.SampleID]
		if !ok || expected.ResultJSON == "" {
			return results, fmt.Errorf("sample %q has no terminal evidence to reproduce", sample.Name)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sample.BundlePath)))
		if err != nil {
			return results, err
		}
		if sha256Hex(data) != sample.SHA256 {
			return results, fmt.Errorf("sample %q bytes changed before rerun", sample.Name)
		}
		outcome, _ := runner.RunSample(ctx, runner.Config{
			HarnessPath: harnessPath, Timeout: timeout,
		}, data)
		var parsed *runner.HarnessResult
		if result, parseErr := runner.ParseHarnessOutput(outcome.Stdout); parseErr == nil {
			parsed = &result
		}
		actualJSON, _, err := runner.NormalizeResult(sample.SHA256, harnessSHA,
			outcome.Stdout, outcome.Stderr, outcome.ExitCode, outcome.Signal,
			outcome.TimedOut, parsed)
		if err != nil {
			return results, err
		}
		var expectedEvidence, actualEvidence runner.Evidence
		if err := json.Unmarshal([]byte(expected.ResultJSON), &expectedEvidence); err != nil {
			return results, err
		}
		if err := json.Unmarshal([]byte(actualJSON), &actualEvidence); err != nil {
			return results, err
		}
		expectedSemantic := makeSemantic(expectedEvidence)
		actualSemantic := makeSemantic(actualEvidence)
		match := reflect.DeepEqual(expectedSemantic, actualSemantic)
		detail := "result matches exported evidence"
		if !match {
			detail = fmt.Sprintf("expected=%+v actual=%+v", expectedSemantic, actualSemantic)
		}
		results = append(results, RerunResult{
			SampleIndex: sample.SampleIndex, Name: sample.Name,
			Classification: actualEvidence.Classification, OK: match, Detail: detail,
		})
	}
	return results, nil
}

func makeSemantic(evidence runner.Evidence) semanticEvidence {
	findings := evidence.Findings
	if findings == nil {
		findings = []string{}
	}
	segments := evidence.MissingSegments
	if segments == nil {
		segments = []runner.MissingSegment{}
	}
	return semanticEvidence{
		Verdict: evidence.Verdict, Classification: evidence.Classification,
		ChainOK: evidence.ChainOK, AnchorPairs: evidence.AnchorPairs,
		ClockOffsetNS: evidence.ClockOffsetNS, Findings: findings,
		MissingSegments: segments, ExitCode: evidence.ExitCode,
		Signal: evidence.Signal, TimedOut: evidence.TimedOut,
	}
}

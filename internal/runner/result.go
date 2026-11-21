package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const ResultSchema = "auditfix.harness.v1"

type MissingSegment struct {
	Device  string `json:"device"`
	SeqFrom int64  `json:"seq_from"`
	SeqTo   int64  `json:"seq_to"`
	Count   int64  `json:"count"`
}

type HarnessResult struct {
	Schema          string           `json:"schema"`
	Verdict         string           `json:"verdict"`
	Classification  string           `json:"classification"`
	ChainOK         bool             `json:"chain_ok"`
	AnchorPairs     int              `json:"anchor_pairs"`
	ClockOffsetNS   int64            `json:"clock_offset_ns"`
	Findings        []string         `json:"findings"`
	MissingSegments []MissingSegment `json:"missing_segments"`
}

type Evidence struct {
	Schema          string           `json:"schema"`
	SampleSHA256    string           `json:"sample_sha256"`
	HarnessSHA256   string           `json:"harness_sha256"`
	ExitCode        int              `json:"exit_code"`
	Signal          int              `json:"signal"`
	TimedOut        bool             `json:"timed_out"`
	Verdict         string           `json:"verdict"`
	Classification  string           `json:"classification"`
	ChainOK         bool             `json:"chain_ok"`
	AnchorPairs     int              `json:"anchor_pairs"`
	ClockOffsetNS   int64            `json:"clock_offset_ns"`
	Findings        []string         `json:"findings"`
	MissingSegments []MissingSegment `json:"missing_segments"`
	StdoutSHA256    string           `json:"stdout_sha256"`
	StderrSHA256    string           `json:"stderr_sha256"`
}

func ParseHarnessOutput(stdout string) (HarnessResult, error) {
	const marker = "AUDITFIX_RESULT "
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, marker) {
			continue
		}
		var result HarnessResult
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &result); err != nil {
			return HarnessResult{}, fmt.Errorf("decode harness result: %w", err)
		}
		if result.Schema != ResultSchema {
			return HarnessResult{}, fmt.Errorf("unsupported harness schema %q", result.Schema)
		}
		if result.Classification == "" {
			return HarnessResult{}, errors.New("harness result has no classification")
		}
		if result.Findings == nil {
			result.Findings = []string{}
		}
		if result.MissingSegments == nil {
			result.MissingSegments = []MissingSegment{}
		}
		return result, nil
	}
	return HarnessResult{}, errors.New("libFuzzer harness produced no AUDITFIX_RESULT line")
}

func NormalizeResult(sampleSHA, harnessSHA, stdout, stderr string,
	exitCode, signal int, timedOut bool, parsed *HarnessResult) (string, string, error) {
	evidence := Evidence{
		Schema:        "auditfix.attempt-evidence.v1",
		SampleSHA256:  sampleSHA,
		HarnessSHA256: harnessSHA,
		ExitCode:      exitCode,
		Signal:        signal,
		TimedOut:      timedOut,
		StdoutSHA256:  sha256Hex([]byte(stdout)),
		StderrSHA256:  sha256Hex([]byte(stderr)),
	}
	if parsed != nil {
		evidence.Verdict = parsed.Verdict
		evidence.Classification = parsed.Classification
		evidence.ChainOK = parsed.ChainOK
		evidence.AnchorPairs = parsed.AnchorPairs
		evidence.ClockOffsetNS = parsed.ClockOffsetNS
		evidence.Findings = parsed.Findings
		evidence.MissingSegments = parsed.MissingSegments
	} else if timedOut {
		evidence.Verdict = "ERROR"
		evidence.Classification = "TIMEOUT"
		evidence.Findings = []string{"HARNESS_TIMEOUT"}
		evidence.MissingSegments = []MissingSegment{}
	} else if signal != 0 || exitCode != 0 {
		evidence.Verdict = "ERROR"
		evidence.Classification = "CRASH"
		evidence.Findings = []string{"HARNESS_CRASH"}
		evidence.MissingSegments = []MissingSegment{}
	} else {
		evidence.Verdict = "ERROR"
		evidence.Classification = "HARNESS_ERROR"
		evidence.Findings = []string{}
		evidence.MissingSegments = []MissingSegment{}
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(append([]byte("auditfix.evidence.v1\n"), data...))
	return string(data), hex.EncodeToString(digest[:]), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

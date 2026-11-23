package fuzz

import (
	"encoding/json"

	"idorfix/internal/detect"
	"idorfix/internal/domain"
	"idorfix/internal/exchange"
)

// Target is the Go entry point exercised by the libFuzzer harness. It must
// never panic on malformed input and must return deterministic verdicts for
// every well-formed sample. The returned code is the libFuzzer convention:
// 0 = accepted input, 1 = bug detected by the harness.
func Target(data []byte) int {
	sample, err := exchange.LoadSampleFile(data)
	if err != nil {
		// Malformed/random fuzzer input is expected and not a finding.
		return 0
	}

	first, err := detect.Analyse(sample)
	if err != nil {
		// Structurally valid but semantically rejected input is also fine.
		return 0
	}
	second, err := detect.Analyse(sample)
	if err != nil {
		return 1
	}

	firstJSON, err := exchange.CanonicalJSON(first)
	if err != nil {
		return 1
	}
	secondJSON, err := exchange.CanonicalJSON(second)
	if err != nil {
		return 1
	}
	if string(firstJSON) != string(secondJSON) {
		return 1
	}

	// Every produced verdict must round-trip through JSON and carry a known
	// outcome. Unknown values indicate a rule-engine contract break.
	if !knownOutcome(first.Outcome) {
		return 1
	}
	var decoded domain.Verdict
	if err := json.Unmarshal(firstJSON, &decoded); err != nil {
		return 1
	}
	return 0
}

func knownOutcome(outcome string) bool {
	switch outcome {
	case domain.VerdictConfirmedIDOR,
		domain.VerdictHorizontalIDOR,
		domain.VerdictVerticalIDOR,
		domain.VerdictInconclusive,
		domain.VerdictBenign:
		return true
	default:
		return false
	}
}

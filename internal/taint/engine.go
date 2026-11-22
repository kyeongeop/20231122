package taint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

const (
	MaxInputBytes = 64 * 1024
	MaxOperations = 256
)

type diagnosticList struct {
	items []model.Diagnostic
}

func (d *diagnosticList) add(level, code, message string) {
	d.items = append(d.items, model.Diagnostic{
		Ordinal: len(d.items) + 1,
		Level:   level,
		Code:    code,
		Message: message,
	})
}

func Execute(data []byte) model.Result {
	result := baseResult(data)
	if len(data) == 0 {
		result.Status = "empty"
		result.Input.State = "empty"
		result.Permission.Decision = "deny"
		finalizeRejected(&result, "empty_input", "input is empty; no arithmetic was evaluated")
		return result
	}
	if len(data) > MaxInputBytes {
		sum := sha256.Sum256(data)
		return oversizedResult(len(data), hex.EncodeToString(sum[:]), data[:256])
	}

	scenario, diagnostic, err := decodeScenario(data)
	if err != nil {
		result.Status = "malformed"
		result.Input.State = "malformed"
		result.Permission.Decision = "deny"
		result.Diagnostics = diagnostic.items
		finalizeRejected(&result, "malformed_input", err.Error())
		return result
	}

	result = executeScenario(scenario, data, diagnostic)
	return result
}

func oversizedResult(size int, digest string, preview []byte) model.Result {
	if len(preview) > 256 {
		preview = preview[:256]
	}
	result := model.Result{
		SchemaVersion: model.ResultSchema,
		CaseID:        "case-" + digest[:12],
		TraceID:       "trace-" + digest[:12],
		Status:        "oversized",
		Input: model.InputSummary{
			Format:           detectFormat(preview),
			SizeBytes:        size,
			SHA256:           digest,
			State:            "oversized",
			PreviewHex:       hex.EncodeToString(preview),
			PreviewTruncated: size > len(preview),
			RawComplete:      false,
		},
		Attack: model.AttackInput{
			Operations: []model.Operation{},
			TaintPath:  []model.TaintStep{},
		},
		Permission: model.PermissionResult{
			BaselineDecision:  "deny",
			EffectiveDecision: "deny",
			Decision:          "deny",
		},
		Evidence: model.Evidence{
			Events: []model.LogEvent{},
			Key:    []model.EvidencePointer{},
		},
		Diagnostics: []model.Diagnostic{},
	}
	finalizeRejected(&result, "oversized_input", fmt.Sprintf(
		"input is %d bytes; limit is %d bytes", size, MaxInputBytes))
	return result
}

func ExecuteJSON(data []byte) model.Result {
	return Execute(data)
}

func baseResult(data []byte) model.Result {
	digest := canonical.SumBytes(data)
	preview := data
	if len(preview) > 256 {
		preview = preview[:256]
	}
	rawHex := ""
	rawComplete := len(data) <= MaxInputBytes
	if rawComplete {
		rawHex = hex.EncodeToString(data)
	}
	return model.Result{
		SchemaVersion: model.ResultSchema,
		CaseID:        "case-" + digest[:12],
		TraceID:       "trace-" + digest[:12],
		Status:        "accepted",
		Input: model.InputSummary{
			Format:           detectFormat(data),
			SizeBytes:        len(data),
			SHA256:           digest,
			State:            "pending",
			PreviewHex:       hex.EncodeToString(preview),
			PreviewTruncated: len(data) > len(preview),
			RawHex:           rawHex,
			RawComplete:      rawComplete,
		},
		Attack: model.AttackInput{
			Operations: []model.Operation{},
			TaintPath:  []model.TaintStep{},
		},
		Trigger: model.Trigger{},
		Permission: model.PermissionResult{
			BaselineDecision:  "deny",
			EffectiveDecision: "deny",
			Decision:          "deny",
		},
		Evidence: model.Evidence{
			Events: []model.LogEvent{},
			Key:    []model.EvidencePointer{},
		},
		Diagnostics: []model.Diagnostic{},
	}
}

func detectFormat(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "json"
	}
	return "unknown"
}

func decodeScenario(data []byte) (model.Scenario, diagnosticList, error) {
	var diagnostics diagnosticList
	var scenario model.Scenario
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scenario); err != nil {
		return scenario, diagnostics, fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return scenario, diagnostics, fmt.Errorf("decode JSON: multiple top-level values")
		}
		return scenario, diagnostics, fmt.Errorf("decode JSON trailing data: %w", err)
	}
	if scenario.SchemaVersion != "" && scenario.SchemaVersion != model.SchemaVersion {
		return scenario, diagnostics, fmt.Errorf(
			"unsupported schema_version %q (want %q)",
			scenario.SchemaVersion, model.SchemaVersion)
	}
	if len(scenario.Operations) > MaxOperations {
		return scenario, diagnostics, fmt.Errorf(
			"operation count %d exceeds limit %d",
			len(scenario.Operations), MaxOperations)
	}
	if scenario.Boundary.Max < scenario.Boundary.Min {
		diagnostics.add("warning", "invalid_boundary",
			"boundary.max is smaller than boundary.min")
	}
	policy := strings.TrimSpace(scenario.Permission.Policy)
	if policy != "" && policy != "exact_effective_token" {
		return scenario, diagnostics, fmt.Errorf(
			"unsupported permission policy %q", policy)
	}
	if scenario.Source.Label == "" {
		diagnostics.add("info", "empty_source_label",
			"source.label is empty; the source value remains auditable")
	}
	return scenario, diagnostics, nil
}

func finalizeRejected(result *model.Result, code, message string) {
	result.Diagnostics = append(result.Diagnostics, model.Diagnostic{
		Ordinal: len(result.Diagnostics) + 1,
		Level:   "high",
		Code:    code,
		Message: message,
	})
	inputPointer := model.EvidencePointer{
		Kind:   "input",
		Ref:    "sha256:" + result.Input.SHA256,
		SHA256: result.Input.SHA256,
		Note:   fmt.Sprintf("%s input, %d bytes", result.Input.State, result.Input.SizeBytes),
	}
	result.Evidence.Key = append(result.Evidence.Key, inputPointer)
	result.Evidence.SHA256 = canonical.Sum(struct {
		Status string                  `json:"status"`
		Input  model.InputSummary      `json:"input"`
		Key    []model.EvidencePointer `json:"key_evidence"`
	}{
		Status: result.Status,
		Input:  result.Input,
		Key:    result.Evidence.Key,
	})
}

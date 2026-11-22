package taint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

func loadSample(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/cases/unsynced-truncation.json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	return data
}

func TestUnsyncedTruncationScenario(t *testing.T) {
	data := loadSample(t)
	result := Execute(data)

	if result.Status != "accepted" || result.Input.State != "accepted" {
		t.Fatalf("unexpected status: %#v", result.Input)
	}
	if result.CaseID != "case-unsynced-truncation" || result.TraceID != "trace-demo-001" {
		t.Fatalf("case identity changed: %s/%s", result.CaseID, result.TraceID)
	}
	if len(result.Attack.TaintPath) != 2 {
		t.Fatalf("taint path length = %d, want 2", len(result.Attack.TaintPath))
	}
	if got := result.Attack.TaintPath[0].After; got != 4294967303 {
		t.Fatalf("add result = %d, want 4294967303", got)
	}
	if !result.Trigger.Detected {
		t.Fatal("tainted truncation was not detected")
	}
	if result.Trigger.OperationSeq != 2 || result.Trigger.Before != 4294967303 ||
		result.Trigger.After != 7 || result.Trigger.WidthBits != 32 {
		t.Fatalf("unexpected trigger: %#v", result.Trigger)
	}
	if !result.Trigger.BoundaryCrossed {
		t.Fatal("boundary overrun was not recorded")
	}
	if result.Permission.BaselineDecision != "deny" ||
		result.Permission.EffectiveDecision != "allow" ||
		!result.Permission.Mismatch || !result.Permission.TaintedEscalation {
		t.Fatalf("unexpected permission result: %#v", result.Permission)
	}
	if len(result.Evidence.Events) != 4 {
		t.Fatalf("event count = %d, want 4", len(result.Evidence.Events))
	}
	for i, event := range result.Evidence.Events {
		if event.Ordinal != i+1 || event.CausalOrder != i+1 {
			t.Fatalf("event order changed at %d: %#v", i, event)
		}
	}
	if !result.Evidence.Clock.Detected ||
		!result.Evidence.Clock.WallRegression ||
		result.Evidence.Clock.SkewMS != -300000 {
		t.Fatalf("unexpected clock anomaly: %#v", result.Evidence.Clock)
	}
	if result.Evidence.SHA256 == "" || len(result.Evidence.Key) < 6 {
		t.Fatalf("evidence was not sealed: %#v", result.Evidence)
	}
}

func TestEmptyAndOversizedInputsAreEvidence(t *testing.T) {
	empty := Execute(nil)
	if empty.Status != "empty" || empty.Input.State != "empty" ||
		empty.Input.SHA256 != canonical.SumBytes(nil) || empty.Permission.Decision != "deny" {
		t.Fatalf("empty input handling: %#v", empty)
	}
	if len(empty.Evidence.Key) != 1 || empty.Evidence.SHA256 == "" {
		t.Fatalf("empty input evidence: %#v", empty.Evidence)
	}

	oversizedBytes := bytes.Repeat([]byte("A"), MaxInputBytes+1)
	oversized := Execute(oversizedBytes)
	if oversized.Status != "oversized" || oversized.Input.State != "oversized" {
		t.Fatalf("oversized status: %#v", oversized.Input)
	}
	if oversized.Input.SizeBytes != MaxInputBytes+1 ||
		oversized.Input.SHA256 != canonical.SumBytes(oversizedBytes) ||
		!oversized.Input.PreviewTruncated ||
		len(oversized.Input.PreviewHex) != 512 ||
		oversized.Input.RawComplete || oversized.Input.RawHex != "" {
		t.Fatalf("oversized evidence: %#v", oversized.Input)
	}
	if oversized.Permission.Decision != "deny" || len(oversized.Diagnostics) != 1 {
		t.Fatalf("oversized decision: %#v", oversized.Permission)
	}
}

func TestMalformedInputIsRejectedWithoutPanic(t *testing.T) {
	result := Execute([]byte(`{"source":`))
	if result.Status != "malformed" || result.Permission.Decision != "deny" {
		t.Fatalf("malformed result: %#v", result)
	}
	if result.Input.SHA256 == "" || result.Evidence.SHA256 == "" {
		t.Fatal("malformed input digest was not retained")
	}
}

func TestExecuteReaderMatchesByteExecution(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		loadSample(t),
		bytes.Repeat([]byte("R"), MaxInputBytes+1),
	} {
		fromBytes := Execute(input)
		fromReader, err := ExecuteReader(bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		left, _ := json.Marshal(fromBytes)
		right, _ := json.Marshal(fromReader)
		if !bytes.Equal(left, right) {
			t.Fatalf("reader and byte execution differ for %d bytes", len(input))
		}
	}
}

func TestExecuteReaderHandlesLargeStream(t *testing.T) {
	const size = 4 * 1024 * 1024
	result, err := ExecuteReader(io.LimitReader(zeroReader{}, size))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "oversized" || result.Input.SizeBytes != size ||
		result.Input.RawComplete || len(result.Input.PreviewHex) != 512 {
		t.Fatalf("large stream result: %#v", result.Input)
	}
	hasher := sha256.New()
	_, _ = io.Copy(hasher, io.LimitReader(zeroReader{}, size))
	if result.Input.SHA256 != hex.EncodeToString(hasher.Sum(nil)) {
		t.Fatalf("large stream digest = %s", result.Input.SHA256)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}

func TestResultJSONIsStableAndOrdered(t *testing.T) {
	data := loadSample(t)
	first := Execute(data)
	second := Execute(data)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("same input produced different result JSON")
	}
	prefix := `{"schema_version":"taintlab-result/v1","case_id":"case-unsynced-truncation","trace_id":"trace-demo-001","status":"accepted"`
	if !strings.HasPrefix(string(firstJSON), prefix) {
		t.Fatalf("top-level field order changed:\n%s", firstJSON[:min(len(firstJSON), 256)])
	}
}

func TestBoundaryAndArithmeticCases(t *testing.T) {
	tests := []struct {
		name       string
		value      int64
		operations []model.Operation
		wantAfter  int64
		wantWrap   bool
	}{
		{"int32 max truncates in place", 2147483647, []model.Operation{{Kind: "trunc", WidthBits: 32}}, 2147483647, false},
		{"int32 max plus one wraps to min", 2147483648, []model.Operation{{Kind: "trunc", WidthBits: 32}}, -2147483648, false},
		{"int32 min stays min", -2147483648, []model.Operation{{Kind: "trunc", WidthBits: 32}}, -2147483648, false},
		{"eight bit wrap", 255, []model.Operation{{Kind: "trunc", WidthBits: 8}}, -1, false},
		{"int64 add wraps", 9223372036854775807, []model.Operation{{Kind: "add", Operand: 1}}, -9223372036854775808, true},
		{"int64 mul wraps", 9223372036854775807, []model.Operation{{Kind: "mul", Operand: 2}}, -2, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := model.Scenario{
				SchemaVersion: model.SchemaVersion,
				CaseID:        "boundary",
				TraceID:       "boundary-trace",
				Source:        model.Source{Label: "input", Value: test.value, Tainted: true},
				Operations:    test.operations,
				Boundary:      model.Boundary{Min: -2147483648, Max: 2147483647},
				Permission:    model.Permission{Policy: "exact_effective_token", RequiredToken: 7},
			}
			raw, err := json.Marshal(scenario)
			if err != nil {
				t.Fatal(err)
			}
			result := Execute(raw)
			if len(result.Attack.TaintPath) != 1 {
				t.Fatalf("taint path: %#v", result.Attack.TaintPath)
			}
			step := result.Attack.TaintPath[0]
			if step.After != test.wantAfter || step.Wrapped != test.wantWrap {
				t.Fatalf("step = %#v, want after=%d wrapped=%t", step, test.wantAfter, test.wantWrap)
			}
		})
	}
}

func TestUntaintedInputDoesNotTrigger(t *testing.T) {
	scenario := model.Scenario{
		SchemaVersion: model.SchemaVersion,
		Source:        model.Source{Label: "trusted.config", Value: 4294967303, Tainted: false},
		Operations:    []model.Operation{{Seq: 1, Kind: "trunc", WidthBits: 32}},
		Boundary:      model.Boundary{Min: 0, Max: 2147483647},
		Permission:    model.Permission{RequiredToken: 7},
	}
	raw, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	result := Execute(raw)
	if result.Trigger.Detected || result.Permission.TaintedEscalation {
		t.Fatalf("untainted value triggered: %#v %#v", result.Trigger, result.Permission)
	}
}

func TestWideTruncationDoesNotTrigger(t *testing.T) {
	scenario := model.Scenario{
		SchemaVersion: model.SchemaVersion,
		Source:        model.Source{Label: "same.width", Value: 99, Tainted: true},
		Operations:    []model.Operation{{Seq: 1, Kind: "trunc", WidthBits: 64}},
		Boundary:      model.Boundary{Min: 0, Max: 100},
		Permission:    model.Permission{RequiredToken: 99},
	}
	raw, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	result := Execute(raw)
	if result.Trigger.Detected {
		t.Fatalf("64-bit truncation was treated as narrowing: %#v", result.Trigger)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

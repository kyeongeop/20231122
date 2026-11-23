package exchange

import (
	"strings"
	"testing"
	"time"

	"idorfix/internal/domain"
)

func TestCanonicalJSONPreservesStructFieldOrder(t *testing.T) {
	sample := domain.Sample{
		SchemaVersion: 1,
		SampleID:      "order-test",
		CreatedAt:     time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC),
	}
	raw, err := CanonicalJSON(sample)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	text := string(raw)
	indexSchema := strings.Index(text, `"schema_version"`)
	indexSample := strings.Index(text, `"sample_id"`)
	indexTitle := strings.Index(text, `"title"`)
	if !(indexSchema < indexSample && indexSample < indexTitle) {
		t.Fatalf("field order not preserved: %s", text)
	}
}

func TestCanonicalJSONIsStableAcrossRuns(t *testing.T) {
	value := map[string]any{"b": 2, "a": 1, "nested": map[string]int{"z": 26, "m": 13}}
	first, err := CanonicalJSON(value)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := CanonicalJSON(value)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonical output unstable: %s vs %s", first, second)
	}
	if !strings.HasPrefix(string(first), `{"a":1,"b":2,"nested":{`) {
		t.Fatalf("map keys not sorted: %s", first)
	}
}

func TestAssertFieldOrderRejectsReorderedFields(t *testing.T) {
	good := `{"schema_version":1,"sample_id":"x","title":"t","attack_class":"c","clocks":[],"events":[],"note":"","input_sha256":"","created_at":"2026-11-23T00:00:00Z"}`
	if err := AssertFieldOrder([]byte(good), domain.Sample{}); err != nil {
		t.Fatalf("good payload rejected: %v", err)
	}

	bad := `{"sample_id":"x","schema_version":1,"title":"t","attack_class":"c","clocks":[],"events":[],"note":"","input_sha256":"","created_at":"2026-11-23T00:00:00Z"}`
	if err := AssertFieldOrder([]byte(bad), domain.Sample{}); err == nil {
		t.Fatal("reordered payload should be rejected")
	}
}

func TestSHA256HexStable(t *testing.T) {
	got := SHA256Hex([]byte("idorfix"))
	if len(got) != 64 {
		t.Fatalf("unexpected digest length %d", len(got))
	}
	if got != SHA256Hex([]byte("idorfix")) {
		t.Fatal("digest not stable")
	}
}

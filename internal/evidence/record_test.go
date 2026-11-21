package evidence

import (
	"testing"
	"time"
)

func sample() Record {
	return Record{
		ID: "ev-0001", Object: "forge", AttackHash: "ab12",
		Trigger: "pipeline.go:120", Decision: "deny", Reason: "rejected",
		Logs:      []LogRef{{Seq: 1, Level: "audit", Message: "checked"}},
		CreatedAt: time.Date(2026, 11, 22, 1, 2, 3, 0, time.UTC),
	}
}

func TestRoundTripBothFormats(t *testing.T) {
	for _, format := range []int{FormatV1, FormatV2} {
		b, err := Marshal(sample(), format)
		if err != nil {
			t.Fatalf("marshal v%d: %v", format, err)
		}
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatalf("unmarshal v%d: %v", format, err)
		}
		if got.ID != "ev-0001" || got.Decision != "deny" || got.Trigger == "" {
			t.Fatalf("v%d lost key evidence: %+v", format, got)
		}
		if len(got.Logs) != 1 {
			t.Fatalf("v%d lost logs: %+v", format, got)
		}
	}
}

func TestUnmarshalLegacyShape(t *testing.T) {
	legacy := `{"id":"ev-9","object":"old","attack_hash":"ff","trigger":"x.go:1",` +
		`"decision":"allow","reason":"ok","log_lines":["info hi"],` +
		`"created_at":"2026-11-22T00:00:00Z"}`
	got, err := Unmarshal([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != FormatV1 || got.Object != "old" || got.Logs[0].Message != "info hi" {
		t.Fatalf("legacy decode wrong: %+v", got)
	}
}

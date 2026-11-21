package parse

import (
	"testing"

	"lfireview/internal/model"
)

func TestDecodeV1Complete(t *testing.T) {
	data := []byte(`{
		"correlation_id": "LFI-1",
		"payload": "../../etc/passwd",
		"trigger_file": "fs.go",
		"trigger_line": 12,
		"trigger_symbol": "Serve",
		"access_verdict": "allow",
		"access_rule": "prefix",
		"log_file": "access.log",
		"log_line": 99,
		"log_evidence": "200 ok"
	}`)
	rec, err := Decode(VersionV1, "o.json", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Status != model.StatusOK {
		t.Fatalf("status = %s, want ok", rec.Status)
	}
	if rec.CorrelationID != "LFI-1" || rec.AttackInput != "../../etc/passwd" {
		t.Fatalf("core fields lost: %+v", rec)
	}
	if rec.PermissionDecision != model.PermitAll {
		t.Fatalf("verdict = %s, want permit", rec.PermissionDecision)
	}
	if rec.TriggerLine != 12 || rec.LogLine != 99 {
		t.Fatalf("numeric fields lost: %+v", rec)
	}
	if string(rec.Raw) != string(data) {
		t.Fatal("raw bytes not retained")
	}
}

func TestDecodeV2CompleteAndAliases(t *testing.T) {
	data := []byte(`{
		"schema": "lfi-evidence/v2",
		"incident": {
			"correlation_id": "LFI-2",
			"attack": {"input": "/etc/shadow", "encoding": "plain"},
			"trigger": {"file": "t.go", "line": 7, "symbol": "Load"},
			"permission": {"decision": "blocked", "rule": "deny-list"},
			"log": {"path": "a.log", "line": 5, "snippet": "403"}
		}
	}`)
	rec, err := Decode(VersionV2, "o.json", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Status != model.StatusOK {
		t.Fatalf("status = %s, want ok", rec.Status)
	}
	if rec.CorrelationID != "LFI-2" || rec.TriggerSymbol != "Load" {
		t.Fatalf("nested fields lost: %+v", rec)
	}
	if rec.PermissionDecision != model.DenyAll {
		t.Fatalf("blocked should normalize to deny, got %s", rec.PermissionDecision)
	}
}

func TestDecodeTruncatedV1RecoversPrefix(t *testing.T) {
	// Cut off after log_line: no closing values, no closing brace.
	data := []byte(`{
		"correlation_id": "LFI-3",
		"payload": "php://filter/resource=db.yaml",
		"trigger_file": "template.go",
		"trigger_line": 56,
		"trigger_symbol": "loadTemplate",
		"access_verdict": "permit",
		"access_rule": "wrapper",
		"log_file": "access.log",
		"log_line": 130`)
	rec, err := Decode(VersionV1, "cut.json", data)
	if err != nil {
		t.Fatalf("decode must not error on truncation: %v", err)
	}
	if rec.Status != model.StatusTruncated {
		t.Fatalf("status = %s, want truncated", rec.Status)
	}
	if rec.ParseError == "" {
		t.Fatal("truncated record must carry a parse error reason")
	}
	if rec.CorrelationID != "LFI-3" || rec.TriggerLine != 56 || rec.LogLine != 130 {
		t.Fatalf("prefix not recovered: %+v", rec)
	}
	if rec.LogSnippet != "" {
		t.Fatalf("field beyond the cut must stay empty, got %q", rec.LogSnippet)
	}
	if string(rec.Raw) != string(data) {
		t.Fatal("truncated raw bytes must be retained as evidence")
	}
}

func TestDecodeTruncatedV2RecoversNestedPrefix(t *testing.T) {
	data := []byte(`{
		"schema": "lfi-evidence/v2",
		"incident": {
			"correlation_id": "LFI-4",
			"attack": {"input": "/proc/self/environ"},
			"trigger": {"file": "d.go", "line": 4`)
	rec, err := Decode(VersionV2, "cut.json", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Status != model.StatusTruncated {
		t.Fatalf("status = %s, want truncated", rec.Status)
	}
	if rec.CorrelationID != "LFI-4" || rec.AttackInput != "/proc/self/environ" {
		t.Fatalf("nested prefix not recovered: %+v", rec)
	}
	if rec.TriggerFile != "d.go" {
		t.Fatalf("trigger file not recovered, got %+v", rec.TriggerFile)
	}
}

func TestDecodeMalformedAndEmpty(t *testing.T) {
	cases := map[string][]byte{
		"garbage": []byte(`###not-json###`),
		"empty":   nil,
		"spaces":  []byte("   "),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			rec, err := Decode(VersionV1, name, data)
			if err != nil {
				t.Fatalf("decode never errors, got %v", err)
			}
			if rec.Status != model.StatusMalformed {
				t.Fatalf("status = %s, want malformed", rec.Status)
			}
		})
	}
}

func TestDecodeUnknownVersion(t *testing.T) {
	rec, err := Decode("v9", "x.json", []byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Status != model.StatusMalformed {
		t.Fatalf("status = %s, want malformed", rec.Status)
	}
}

func TestIsTruncation(t *testing.T) {
	if !isTruncation(errEOF("unexpected end of JSON input")) {
		t.Fatal("unexpected end of JSON input must count as truncation")
	}
	if isTruncation(errEOF("invalid character '#' looking for beginning")) {
		t.Fatal("syntax error must not count as truncation")
	}
}

type errEOF string

func (e errEOF) Error() string { return string(e) }

func FuzzDecode(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"correlation_id":"x"}`),
		[]byte(`{"incident":{"correlation_id":"x","attack":{"input":".."`),
		nil,
		[]byte(`{`),
		[]byte(`[]`),
		[]byte("\"\xff\xfe"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Both version paths must survive arbitrary input without panicking.
		if _, err := Decode(VersionV1, "fuzz", data); err != nil {
			t.Fatalf("v1 decode returned error: %v", err)
		}
		if _, err := Decode(VersionV2, "fuzz", data); err != nil {
			t.Fatalf("v2 decode returned error: %v", err)
		}
	})
}

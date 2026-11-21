package evidence

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func sampleRecord() *Record {
	return &Record{
		TS: "2026-11-22T00:00:00Z", Scenario: "missing_fragment",
		InputSHA256: strings.Repeat("a", 64), InputLen: 77,
		AttackVector: "block[0].frag_id references missing fragment",
		TriggerFunc:  "bombverify/internal/decomp.Decompress",
		TriggerFile:  "internal/decomp/decomp.go", TriggerLine: 126,
		PermSubject: "verifier", PermAction: "decompress.execute",
		PermDecision: "allow", PermReason: "granted",
		QuotaMaxOutputBytes: 4 << 20, QuotaMaxExpansionRatio: 100,
		LogFile: "artifacts/audit.log", LogDigest: strings.Repeat("b", 64),
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	rec := sampleRecord()
	if err := src.Insert(rec); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := src.ExportJSONL(&buf); err != nil {
		t.Fatal(err)
	}

	// The exported line must list keys in FieldOrder.
	line := strings.TrimSpace(buf.String())
	var keys []string
	dec := json.NewDecoder(strings.NewReader(line))
	tok, _ := dec.Token()
	if tok != json.Delim('{') {
		t.Fatal("not an object")
	}
	for dec.More() {
		kt, _ := dec.Token()
		keys = append(keys, kt.(string))
		var v any
		dec.Decode(&v)
	}
	if strings.Join(keys, ",") != strings.Join(FieldOrder, ",") {
		t.Fatalf("key order %v, want %v", keys, FieldOrder)
	}

	dst, err := Open(filepath.Join(dir, "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := dst.ImportJSONL(&buf); err != nil {
		t.Fatal(err)
	}
	n, err := src.VerifyReload(dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("verified %d records, want 1", n)
	}
}

func TestImportRejectsReorderedKeys(t *testing.T) {
	dst, err := Open(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	b, err := json.Marshal(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}
	// Swap the first two keys to break the canonical order.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString(`{"ts":`)
	sb.WriteString(string(m["ts"]))
	sb.WriteString(`,"record_id":`)
	sb.WriteString(string(m["record_id"]))
	for _, k := range FieldOrder[2:] {
		sb.WriteString(",")
		kb, _ := json.Marshal(k)
		sb.Write(kb)
		sb.WriteString(":")
		sb.WriteString(string(m[k]))
	}
	sb.WriteString("}")
	if _, err := dst.ImportJSONL(strings.NewReader(sb.String())); err == nil {
		t.Fatal("reordered keys were accepted")
	}
}

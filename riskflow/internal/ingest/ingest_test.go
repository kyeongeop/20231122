package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"riskflow/internal/model"
)

func TestDetectFormats(t *testing.T) {
	v1 := []byte(`{"record_id":"a","package":"p"}` + "\n")
	if got := Detect(v1); got != model.SchemaV1 {
		t.Fatalf("v1 detection = %s", got)
	}
	v2 := []byte("42\n{}\n")
	if got := Detect(v2); got != model.SchemaV2 {
		t.Fatalf("v2 detection = %s", got)
	}
}

func TestParseV1RoundTrip(t *testing.T) {
	raw := []byte(`{"record_id":"R1","package":"pkg","version":"1.0","role":"guest","decision":"allow"}` + "\n")
	out, err := Parse("b", raw)
	if err != nil {
		t.Fatalf("parse v1: %v", err)
	}
	if len(out.Records) != 1 || out.Records[0].RecordID != "R1" {
		t.Fatalf("unexpected records: %+v", out.Records)
	}
	if out.Records[0].InputHash == "" {
		t.Fatal("input hash not bound")
	}
}

func TestParseV1Truncation(t *testing.T) {
	raw := []byte(`{"record_id":"R1","package":"pkg"}` + "\n" + `{"record_id":"R2","packa`)
	out, err := Parse("b", raw)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	if !out.Truncated || len(out.Records) != 1 {
		t.Fatalf("truncation not isolated: %+v", out)
	}
}

func TestParseV2ChecksumAndTruncation(t *testing.T) {
	rec := model.Record{RecordID: "R9", Package: "pkg", Version: "2.0",
		Severity: "high", Decision: "allow", Role: "approver"}
	full := mustFrame(t, rec)

	out, err := Parse("b", full)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if len(out.Records) != 1 || out.Schema != model.SchemaV2 {
		t.Fatalf("v2 round trip failed: %+v", out)
	}

	// Cut the frame so the declared length exceeds available bytes.
	cut := len(full) - 10
	_, err = Parse("b", full[:cut])
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want truncated v2, got %v", err)
	}
}

func TestParseV2BadChecksum(t *testing.T) {
	rec := model.Record{RecordID: "R9", Package: "pkg"}
	frame := mustFrame(t, rec)
	// Flip a payload byte inside the JSON body while keeping the frame length.
	idx := indexByte(frame, 'p')
	frame[idx] = 'x'
	_, err := Parse("b", frame)
	if err == nil || errors.Is(err, ErrTruncated) {
		t.Fatalf("want checksum error, got %v", err)
	}
}

func mustFrame(t *testing.T, rec model.Record) []byte {
	t.Helper()
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	env := model.Envelope{Schema: model.SchemaV2, BatchID: "b",
		Checksum: hex.EncodeToString(sum[:]), Payload: rec}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(itoa(len(body))+"\n"), body...)
	return append(frame, '\n')
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

package decomp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRoundTripOK(t *testing.T) {
	dict := []byte("shared-dictionary")
	raw := bytes.Repeat([]byte("abc"), 100)
	data, err := Build(
		[]Fragment{{ID: 1, Data: dict}},
		[]BlockSpec{{Codec: 1, Frag: 1, Raw: raw}},
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Decompress(data, DefaultQuota(), DiscardLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpandedBytes != int64(len(raw)) {
		t.Fatalf("expanded %d, want %d", res.ExpandedBytes, len(raw))
	}
	if res.ExpansionCount == 0 {
		t.Fatal("expansion count not tracked")
	}
}

func TestMissingFragment(t *testing.T) {
	data, err := Build(
		[]Fragment{{ID: 1, Data: []byte("d")}},
		[]BlockSpec{{Codec: 1, Frag: 42, Raw: []byte("x")}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, derr := Decompress(data, DefaultQuota(), DiscardLogger{})
	var de *Error
	if !errors.As(derr, &de) {
		t.Fatalf("want *Error, got %v", derr)
	}
	if !strings.Contains(de.Reason, ErrMissingFragment.Error()) {
		t.Fatalf("reason %q does not mention missing fragment", de.Reason)
	}
	if de.Line == 0 || de.Func == "" {
		t.Fatalf("trigger location not captured: %+v", de)
	}
}

func TestEmptyInput(t *testing.T) {
	_, err := Decompress(nil, DefaultQuota(), DiscardLogger{})
	var de *Error
	if !errors.As(err, &de) || !strings.Contains(de.Reason, ErrEmptyInput.Error()) {
		t.Fatalf("got %v", err)
	}
}

func TestOversizeInput(t *testing.T) {
	q := DefaultQuota()
	_, err := Decompress(make([]byte, q.MaxInputBytes+1), q, DiscardLogger{})
	var de *Error
	if !errors.As(err, &de) || !strings.Contains(de.Reason, ErrOversizeInput.Error()) {
		t.Fatalf("got %v", err)
	}
}

func TestZipBombQuota(t *testing.T) {
	data, err := Build(nil, []BlockSpec{{Codec: 1, Frag: NoFragment, Raw: make([]byte, 8<<20)}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Decompress(data, DefaultQuota(), DiscardLogger{})
	if err == nil {
		t.Fatal("zip bomb was not rejected")
	}
	if res.ExpandedBytes > DefaultQuota().MaxOutputBytes {
		t.Fatalf("quota breached: expanded %d", res.ExpandedBytes)
	}
}

func TestTruncatedHeader(t *testing.T) {
	if _, err := Decompress([]byte("BM"), DefaultQuota(), DiscardLogger{}); err == nil {
		t.Fatal("truncated header accepted")
	}
}

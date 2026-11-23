package record

import (
	"errors"
	"testing"
)

func TestRoundTripV1(t *testing.T) {
	r := Record{TS: 1763850000, Remote: "10.1.2.10", XFF: "203.0.113.50", Action: "allow"}
	got, err := Decode(EncodeV1(r))
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != FormatV1 || got.Remote != r.Remote || got.XFF != r.XFF || got.Action != r.Action {
		t.Fatalf("v1 roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripV1EmptyXFF(t *testing.T) {
	r := Record{TS: 1, Remote: "198.51.100.7", Action: "allow"}
	got, err := Decode(EncodeV1(r))
	if err != nil {
		t.Fatal(err)
	}
	if got.XFF != "" {
		t.Fatalf("expected empty xff, got %q", got.XFF)
	}
}

func TestRoundTripV2(t *testing.T) {
	r := Record{TS: 2, Remote: "203.0.113.9", XFF: "10.0.0.5", Action: "deny",
		Rule: "R3-xff-spoof", Reason: "spoof"}
	got, err := Decode(EncodeV2(r))
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != FormatV2 || got.Rule != r.Rule || got.Reason != r.Reason {
		t.Fatalf("v2 roundtrip mismatch: %+v", got)
	}
}

func TestTruncatedV2Detected(t *testing.T) {
	full := EncodeV2(Record{TS: 3, Remote: "10.1.2.10", XFF: "8.8.8.8", Action: "allow"})
	cut := full[:len(full)/2]
	_, err := Decode(cut)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}

func TestTruncatedV1Detected(t *testing.T) {
	_, err := Decode([]byte("v1|1763850000|10.1.2.10"))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}

// FuzzDecode feeds arbitrary bytes to the decoder: it must never panic
// and any successful decode must re-encode to a decodable record.
func FuzzDecode(f *testing.F) {
	f.Add([]byte("v1|1763850000|10.1.2.10|203.0.113.50|allow"))
	f.Add([]byte(`{"v":2,"ts":1,"remote":"10.1.2.10","xff":"8.8.8.8","action":"deny"}`))
	f.Add([]byte("v1|"))
	f.Add([]byte("{"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Decode(data)
		if err != nil {
			return
		}
		var enc []byte
		if r.Format == FormatV1 {
			enc = EncodeV1(r)
		} else {
			enc = EncodeV2(r)
		}
		if _, err := Decode(enc); err != nil {
			t.Fatalf("re-encode of %+v undecodable: %v", r, err)
		}
	})
}

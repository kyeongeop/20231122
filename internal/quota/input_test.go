package quota

import (
	"errors"
	"testing"
)

func TestParseEmptyInput(t *testing.T) {
	_, ev, err := ParseInput(nil)
	if !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("empty: %v", err)
	}
	if ev.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty sha256 mismatch: %s", ev.SHA256)
	}
	if ev.Bytes != 0 || ev.Truncated {
		t.Fatalf("empty evidence wrong: %+v", ev)
	}
}

func TestParseOversizedRetainsPrefixEvidence(t *testing.T) {
	raw := append([]byte(RawBaseline), make([]byte, MaxInputBytes-len(RawBaseline))...)
	for i := len(RawBaseline); i < len(raw); i++ {
		raw[i] = ' '
	}
	_, ev, err := ParseInput(raw)
	if !errors.Is(err, ErrOversized) {
		t.Fatalf("oversize: %v", err)
	}
	if !ev.Truncated || ev.DigestScope != "retained_prefix" || ev.Bytes != MaxInputBytes {
		t.Fatalf("oversize evidence wrong: %+v", ev)
	}
	if ev.SHA256 != "472c59dac92e76c631cf343b35bc47e940d01e1d77ecadd2a4441dcfc88e6183" {
		t.Fatalf("oversize sha256 mismatch: %s", ev.SHA256)
	}
}

func TestParseMissingFragment(t *testing.T) {
	input, ev, err := ParseInput([]byte(RawAttackMissingFragment))
	if !errors.Is(err, ErrFragmentGap) || !IsFragmentMissing(err) {
		t.Fatalf("fragment gap: %v", err)
	}
	if len(ev.MissingFields) != 1 || ev.MissingFields[0] != FragmentField {
		t.Fatalf("missing fields: %+v", ev.MissingFields)
	}
	if input.TenantID != "tenant-red" || input.QuotaCount != 4 {
		t.Fatalf("parsed input lost fields: %+v", input)
	}
}

func TestParseMalformed(t *testing.T) {
	if _, _, err := ParseInput([]byte("{not-json")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed: %v", err)
	}
}

func TestReferenceInputHashes(t *testing.T) {
	want := map[string]string{
		"baseline-complete":       "ce85cf1d2688e3ccb961a8796afd3029220a0ae561c0d348678b9b0704e828fb",
		"attack-missing-fragment": "a77e392cac2f0ce060f944dee9fe329d190c8c0b7d2b761d144b2de8858afbac",
		"capacity-pressure":       "a383199237468876f572f11778ce6349cd6adf36fe148022fd9a2e93a040eb18",
	}
	for _, sc := range DefaultScenarios() {
		_, ev, _ := ParseInput(sc.Raw)
		if w, ok := want[sc.Name]; ok && ev.SHA256 != w {
			t.Errorf("%s: %s != %s", sc.Name, ev.SHA256, w)
		}
	}
}

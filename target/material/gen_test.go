package material

import "testing"

func TestLocateOffsetsAndParse(t *testing.T) {
	var cipher, tag [32]byte
	raw := Build(7, 5, 4, 5, cipher, tag)
	if len(raw) != 108 {
		t.Fatalf("unexpected frame size %d", len(raw))
	}
	anchors, err := Locate(raw)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	want := []int64{0, 16, 64}
	for i, a := range anchors {
		if a.Offset != want[i] {
			t.Fatalf("anchor %d offset=%d want %d", i+1, a.Offset, want[i])
		}
	}
	frame, err := Parse(raw, anchors)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if frame.ServerEpoch != 5 || frame.ClientEpoch != 4 || frame.AttestEpoch != 5 {
		t.Fatalf("epoch parse wrong: %+v", frame)
	}
}

func TestLocateMissingAnchor(t *testing.T) {
	if _, err := Locate([]byte("garbage")); err == nil {
		t.Fatal("expected error for missing anchors")
	}
}

func TestBuildDeterministic(t *testing.T) {
	var c, g [32]byte
	a := Build(1, 2, 2, 2, c, g)
	b := Build(1, 2, 2, 2, c, g)
	if SHA256(a) != SHA256(b) {
		t.Fatal("Build is not deterministic for equal inputs")
	}
}

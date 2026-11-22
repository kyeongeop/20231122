package checker

import (
	"strings"
	"testing"
)

func TestSplitAnchorsOffsets(t *testing.T) {
	raw := "ANCHOR1 a.example ANCHOR2 a,example ANCHOR3 exact"
	anchors, findings := splitAnchors(raw)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %v", findings)
	}
	if len(anchors) != 3 {
		t.Fatalf("want 3 anchors, got %d", len(anchors))
	}
	wantOff := []int{0, 18, 36}
	for i, a := range anchors {
		if a.Offset != wantOff[i] {
			t.Errorf("anchor %d marker offset = %d, want %d", i, a.Offset, wantOff[i])
		}
	}
	if got := bodyOffset(raw, anchors, Anchor1, 0); got != len(Anchor1)+1 {
		t.Errorf("body offset ANCHOR1 = %d, want %d", got, len(Anchor1)+1)
	}
}

func TestThreeAnchorAttacks(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		verdict  Verdict
		anchor   string
		code     string
		wantOff  int // anchor marker offset (trigger position)
		wantByte int // exact raw byte offset of the offending byte
	}{
		{
			name:    "anchor1 underscore attack",
			raw:     "ANCHOR1 _evil.example ANCHOR2 _evil,example ANCHOR3 exact",
			verdict: VerdictDeny, anchor: Anchor1, code: "ILLEGAL_CHARACTER", wantOff: 0,
			wantByte: 8,
		},
		{
			name:    "anchor2 label count mismatch",
			raw:     "ANCHOR1 good.example ANCHOR2 onlyonelabel ANCHOR3 exact",
			verdict: VerdictDeny, anchor: Anchor2, code: "LABEL_COUNT_MISMATCH", wantOff: 21,
			wantByte: 29,
		},
		{
			name:    "anchor3 unknown comparison rule",
			raw:     "ANCHOR1 good.example ANCHOR2 good,example ANCHOR3 fuzzy-match",
			verdict: VerdictDeny, anchor: Anchor3, code: "UNKNOWN_RULE", wantOff: 42,
			wantByte: 50,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Evaluate(tc.raw)
			if res.Verdict != tc.verdict {
				t.Fatalf("verdict = %s, want %s (%s)", res.Verdict, tc.verdict, res.Rationale)
			}
			if len(res.Findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			f := res.Findings[0]
			if f.Anchor != tc.anchor || f.Code != tc.code {
				t.Fatalf("first finding = %s/%s, want %s/%s", f.Anchor, f.Code, tc.anchor, tc.code)
			}
			if f.Offset != tc.wantOff || f.ByteOffset != tc.wantByte {
				t.Fatalf("offset = %d/%d, want %d/%d", f.Offset, f.ByteOffset, tc.wantOff, tc.wantByte)
			}
			if res.Evidence["sha256"] != Digest(tc.raw) {
				t.Fatal("evidence sha256 does not anchor to raw input")
			}
		})
	}
}

func TestAllowCase(t *testing.T) {
	raw := "ANCHOR1 good.example ANCHOR2 good,example ANCHOR3 case-insensitive"
	res := Evaluate(raw)
	if res.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow: %s", res.Verdict, res.Rationale)
	}
}

func TestIDNARule(t *testing.T) {
	// High-byte wire names must be rejected at ANCHOR1 even when the supplied
	// punycode labels and the idna comparison rule are themselves consistent.
	raw := "ANCHOR1 straége.example ANCHOR2 xn--strage-5ka,example ANCHOR3 idna"
	res := Evaluate(raw)
	if res.Verdict != VerdictDeny {
		t.Fatalf("verdict = %s, want deny", res.Verdict)
	}
	if res.Findings[0].Anchor != Anchor1 || res.Findings[0].Code != "NON_ASCII_IN_WIRE_NAME" {
		t.Fatalf("first finding = %s/%s, want ANCHOR1/NON_ASCII_IN_WIRE_NAME",
			res.Findings[0].Anchor, res.Findings[0].Code)
	}
	for _, f := range res.Findings {
		if f.Code == "ENCODING_MISMATCH" || f.Code == "COMPARISON_FAILED" {
			t.Fatalf("idna projection should be consistent, got %s: %s", f.Code, f.Message)
		}
	}

	// Pure ASCII name under the idna rule passes all three anchors.
	ascii := "ANCHOR1 Good.Example ANCHOR2 good,example ANCHOR3 idna"
	if r := Evaluate(ascii); r.Verdict != VerdictAllow {
		t.Fatalf("ascii idna verdict = %s, want allow: %s", r.Verdict, r.Rationale)
	}
}

func TestEmptyInput(t *testing.T) {
	res := Evaluate("")
	if res.Verdict != VerdictUndetermined {
		t.Fatalf("verdict = %s, want undetermined", res.Verdict)
	}
	if res.Evidence["raw_len"] != "0" {
		t.Fatal("empty input must retain raw_len=0 evidence")
	}
}

func TestOversizedInput(t *testing.T) {
	raw := strings.Repeat("A", MaxInputBytes+1)
	res := Evaluate(raw)
	if res.Verdict != VerdictUndetermined {
		t.Fatalf("verdict = %s, want undetermined", res.Verdict)
	}
	if len(res.Evidence["raw_prefix_256"]) != 256 {
		t.Fatal("oversized input must retain a 256-byte prefix as evidence")
	}
	if res.Evidence["sha256"] != Digest(raw) {
		t.Fatal("oversized input must retain full-input sha256")
	}
}

func TestNeverPanicsOnGarbage(t *testing.T) {
	garbage := []string{
		"", "ANCHOR1", "ANCHOR3ANCHOR2ANCHOR1",
		"ANCHOR1 \x00\x01\x7f ANCHOR2 ,,, ANCHOR3 ",
		strings.Repeat("ANCHOR1 x ANCHOR2 y ANCHOR3 z ", 1000),
	}
	for _, g := range garbage {
		res := Evaluate(g)
		switch res.Verdict {
		case VerdictDeny, VerdictAllow, VerdictUndetermined:
		default:
			t.Fatalf("unknown verdict %q", res.Verdict)
		}
	}
}

// Package parser tests pin the overflow behavior at every audit anchor and
// confirm both the vulnerable and hardened implementations fail closed.
package parser

import (
	"encoding/binary"
	"errors"
	"testing"
)

func rec9(tag byte, length, offset uint32) [9]byte {
	var r [9]byte
	r[0] = tag
	binary.LittleEndian.PutUint32(r[1:5], length)
	binary.LittleEndian.PutUint32(r[5:9], offset)
	return r
}

func frame1(r [9]byte, pad int) []byte {
	buf := make([]byte, 8+9+pad)
	copy(buf[:4], Magic[:])
	binary.LittleEndian.PutUint32(buf[4:8], 1)
	copy(buf[8:17], r[:])
	return buf
}

func TestEmptyInputFailsClosed(t *testing.T) {
	for name, fn := range map[string]func([]byte) (*Frame, *ParseState, error){
		"vulnerable": ParseVulnerable,
		"hardened":   ParseHardened,
	} {
		if _, _, err := fn(nil); !errors.Is(err, ErrEmpty) {
			t.Fatalf("%s: want ErrEmpty, got %v", name, err)
		}
	}
}

func TestAnchorOverflows(t *testing.T) {
	a2 := frame1(rec9(1, 0x20, 0xFFFFFFF0), 5)
	a3 := frame1(rec9(2, 0xFFFFFFF9, 0), 5)

	if _, st, err := ParseHardened(a2); !errors.Is(err, ErrOverflow) {
		t.Fatalf("A2 hardened: want ErrOverflow, got %v", err)
	} else if _, ok := st.AnchorHits[AnchorOffsetAdd]; !ok {
		t.Fatalf("A2 anchor not marked")
	}
	if _, st, err := ParseHardened(a3); !errors.Is(err, ErrOverflow) {
		t.Fatalf("A3 hardened: want ErrOverflow, got %v", err)
	} else if _, ok := st.AnchorHits[AnchorCursorAdd]; !ok {
		t.Fatalf("A3 anchor not marked")
	}

	if _, st, err := ParseVulnerable(a2); err != nil {
		t.Fatalf("A2 vulnerable should not error, got %v", err)
	} else {
		assertWrap(t, st, AnchorOffsetAdd, 0x10)
	}
	if _, st, err := ParseVulnerable(a3); err != nil {
		t.Fatalf("A3 vulnerable should not error, got %v", err)
	} else {
		assertWrap(t, st, AnchorCursorAdd, 0x01)
	}
}

func TestA1CountScaleOverflow(t *testing.T) {
	buf := make([]byte, 8)
	copy(buf[:4], Magic[:])
	binary.LittleEndian.PutUint32(buf[4:8], 0x20000000)

	if _, st, err := ParseHardened(buf); !errors.Is(err, ErrCountTooBig) {
		t.Fatalf("A1 hardened: want ErrCountTooBig, got %v", err)
	} else if st == nil {
		t.Fatal("hardened state missing")
	}
	_, st, err := ParseVulnerable(buf)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("A1 vulnerable: want ErrTruncated, got %v", err)
	}
	assertWrap(t, st, AnchorCountScale, 0x20000000)
}

func TestOversizedPayloadClaim(t *testing.T) {
	buf := make([]byte, 1<<20)
	copy(buf[:4], Magic[:])
	binary.LittleEndian.PutUint32(buf[4:8], 1)
	head := rec9(3, 0xFFFFFFFF, 0)
	copy(buf[8:17], head[:])

	if _, _, err := ParseHardened(buf); !errors.Is(err, ErrOverflow) {
		t.Fatalf("oversize hardened: want ErrOverflow, got %v", err)
	}
	_, st, err := ParseVulnerable(buf)
	if err != nil {
		t.Fatalf("oversize vulnerable should not error, got %v", err)
	}
	assertWrap(t, st, AnchorCursorAdd, 0x07)
}

func assertWrap(t *testing.T, st *ParseState, anchor string, want uint32) {
	t.Helper()
	for _, w := range st.Wraps {
		if w.Anchor == anchor {
			if w.Wrapped != want {
				t.Fatalf("%s wrapped: want %#x, got %#x", anchor, want, w.Wrapped)
			}
			return
		}
	}
	t.Fatalf("no wrap evidence for %s", anchor)
}

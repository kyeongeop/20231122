// Package decomp parses the BMB1 container format and expands its blocks
// under a strict resource quota. It is the attack surface exercised by the
// libFuzzer harness and the scenario runner.
package decomp

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"runtime"
)

// Magic identifies a BMB1 container.
var Magic = []byte("BMB1")

// NoFragment marks a block that references no dictionary fragment.
const NoFragment = 0xFFFFFFFF

// Quota caps the resources a single Decompress call may consume.
type Quota struct {
	MaxInputBytes     int64
	MaxOutputBytes    int64
	MaxExpansionRatio float64
	MaxBlocks         int
	MaxFragments      int
}

// DefaultQuota returns the deployment quota used by the scenario runner.
func DefaultQuota() Quota {
	return Quota{
		MaxInputBytes:     1 << 20,
		MaxOutputBytes:    4 << 20,
		MaxExpansionRatio: 100.0,
		MaxBlocks:         64,
		MaxFragments:      16,
	}
}

// Result reports what an expansion actually consumed.
type Result struct {
	ExpandedBytes  int64
	ExpansionCount int
	Blocks         int
	Fragments      int
}

// Error carries a reason plus the exact trigger location in this package.
type Error struct {
	Op     string
	Reason string
	Func   string
	File   string
	Line   int
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s (at %s:%d %s)", e.Op, e.Reason, e.File, e.Line, e.Func)
}

func newError(op, reason string) *Error {
	e := &Error{Op: op, Reason: reason}
	if pc, file, line, ok := runtime.Caller(1); ok {
		e.File, e.Line = file, line
		if fn := runtime.FuncForPC(pc); fn != nil {
			e.Func = fn.Name()
		}
	}
	return e
}

// Logger receives structured audit events during expansion.
type Logger interface {
	Log(event string, kv ...any)
}

// DiscardLogger drops all events; used by the fuzz harness.
type DiscardLogger struct{}

// Log implements Logger.
func (DiscardLogger) Log(string, ...any) {}

var (
	ErrEmptyInput      = errors.New("empty input")
	ErrOversizeInput   = errors.New("input exceeds MaxInputBytes")
	ErrMissingFragment = errors.New("block references missing fragment")
)

type block struct {
	codec  byte
	fragID uint32
	clen   uint32
	ulen   uint32
	off    int // offset of cdata inside the container
}

// Decompress parses data as a BMB1 container and expands every block while
// enforcing q. It never allocates more than the remaining output quota.
func Decompress(data []byte, q Quota, log Logger) (*Result, error) {
	res := &Result{}
	if len(data) == 0 {
		return res, newError("parse", ErrEmptyInput.Error())
	}
	if q.MaxInputBytes > 0 && int64(len(data)) > q.MaxInputBytes {
		return res, newError("admit", ErrOversizeInput.Error())
	}
	frags, blocks, err := parse(data, q)
	if err != nil {
		return res, err
	}
	res.Fragments = len(frags)
	res.Blocks = len(blocks)

	out := bytes.NewBuffer(make([]byte, 0, 4096))
	for i, b := range blocks {
		if int64(b.ulen) > q.MaxOutputBytes-int64(out.Len()) {
			return res, newError("expand", fmt.Sprintf(
				"block %d declares %d bytes, exceeds remaining output quota", i, b.ulen))
		}
		var dict []byte
		if b.fragID != NoFragment {
			frag, ok := frags[b.fragID]
			if !ok {
				log.Log("missing_fragment", "block", i, "frag_id", b.fragID)
				return res, newError("expand", fmt.Sprintf(
					"%s: id=%d referenced by block %d", ErrMissingFragment, b.fragID, i))
			}
			dict = frag
			res.ExpansionCount++
		}
		raw := data[b.off : b.off+int(b.clen)]
		n, err := expandBlock(out, b.codec, raw, dict, q.MaxOutputBytes-int64(out.Len()))
		res.ExpansionCount++
		res.ExpandedBytes += n
		if err != nil {
			return res, err
		}
		ratio := float64(res.ExpandedBytes) / float64(maxInt64(int64(len(data)), 1))
		if q.MaxExpansionRatio > 0 && ratio > q.MaxExpansionRatio {
			log.Log("ratio_exceeded", "block", i, "ratio", ratio)
			return res, newError("expand", fmt.Sprintf(
				"expansion ratio %.1f exceeds quota %.1f after block %d", ratio, q.MaxExpansionRatio, i))
		}
	}
	return res, nil
}

func expandBlock(out *bytes.Buffer, codec byte, raw, dict []byte, budget int64) (int64, error) {
	var r io.Reader
	switch codec {
	case 0:
		r = bytes.NewReader(raw)
	case 1:
		if dict != nil {
			r = flate.NewReaderDict(bytes.NewReader(raw), dict)
		} else {
			r = flate.NewReader(bytes.NewReader(raw))
		}
	default:
		return 0, newError("expand", fmt.Sprintf("unknown codec %d", codec))
	}
	n, err := io.Copy(out, io.LimitReader(r, budget+1))
	if err != nil {
		return n, newError("expand", "stream error: "+err.Error())
	}
	if n > budget {
		return n, newError("expand", fmt.Sprintf("block expanded past output quota (%d > %d)", n, budget))
	}
	return n, nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

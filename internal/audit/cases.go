// Package audit builds the anchor scenarios, drives both parser modes,
// evaluates permission decisions and preserves evidence end to end.
package audit

import (
	"encoding/binary"

	"github.com/kyeongeop/20231122/internal/parser"
)

// Case describes one reconstructed attack scenario.
type Case struct {
	ID     string
	Title  string
	Anchor string
	Data   []byte
	Note   string
}

// frame serializes magic + record_count + 9-byte record headers.
func frame(recordCount uint32, records ...[9]byte) []byte {
	buf := make([]byte, 0, 8+len(records)*9)
	buf = append(buf, parser.Magic[:]...)
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], recordCount)
	buf = append(buf, count[:]...)
	for _, rec := range records {
		buf = append(buf, rec[:]...)
	}
	return buf
}

// record builds one 9-byte header: tag(1) length(4) offset(4).
func record(tag byte, length, offset uint32) [9]byte {
	var rec [9]byte
	rec[0] = tag
	binary.LittleEndian.PutUint32(rec[1:5], length)
	binary.LittleEndian.PutUint32(rec[5:9], offset)
	return rec
}

// BuildCases returns the five required scenarios.
func BuildCases() []Case {
	// A1: 0x20000000 * 9 wraps in uint32 (wrapped value 0x20000000).
	a1 := frame(0x20000000)

	// A2: offset 0xFFFFFFF0 + length 0x20 wraps to 0x10. Five padding bytes
	// make the 9-byte header at cursor 13 fully addressable.
	a2 := append(frame(1, record(0x01, 0x20, 0xFFFFFFF0)), make([]byte, 6)...)

	// A3: cursor(8) + length 0xFFFFFFF9 wraps to 1; offset stays 0 so A2 is safe.
	a3 := append(frame(1, record(0x02, 0xFFFFFFF9, 0x00000000)), make([]byte, 5)...)

	// Oversized: 16 MiB body but header claims a 4 GiB payload.
	oversize := make([]byte, 1<<24)
	copy(oversize, parser.Magic[:])
	binary.LittleEndian.PutUint32(oversize[4:8], 1)
	head := record(0x03, 0xFFFFFFFF, 0)
	copy(oversize[8:17], head[:])

	return []Case{
		{ID: "CASE-A1", Title: "header table width overflow", Anchor: parser.AnchorCountScale, Data: a1, Note: "record_count*9 wraps uint32"},
		{ID: "CASE-A2", Title: "offset plus length overflow", Anchor: parser.AnchorOffsetAdd, Data: a2, Note: "0xFFFFFFF0+0x20 wraps to 0x10"},
		{ID: "CASE-A3", Title: "cursor advance overflow", Anchor: parser.AnchorCursorAdd, Data: a3, Note: "8+0xFFFFFFF9 wraps to 0x01"},
		{ID: "CASE-EMPTY", Title: "empty input", Anchor: "-", Data: []byte{}, Note: "zero-byte input must fail closed"},
		{ID: "CASE-OVERSIZE", Title: "oversized input with 4GiB payload claim", Anchor: parser.AnchorCursorAdd, Data: oversize, Note: "16MiB frame claiming uint32-max length"},
	}
}

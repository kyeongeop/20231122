// Package parser implements a small length-prefixed binary record format.
//
// Wire layout (little-endian):
//
//	magic        [4]byte   "PF01"
//	record_count uint32
//	records[record_count]:
//	    tag    uint8
//	    length uint32    (payload length)
//	    offset uint32    (payload offset relative to frame start)
//	    payload[length]
//
// The frame is parsed under a ParseState (cursor + remaining budget) so the
// same byte stream can be replayed deterministically during audit.
package parser

import "errors"

// Magic is the 4-byte frame prefix.
var Magic = [4]byte{'P', 'F', '0', '1'}

// Anchors are the three fixed audit trigger points inside one frame.
// Each anchor names the exact arithmetic site that an overflow case must hit.
const (
	AnchorCountScale = "A1:count*9" // record_count * recordHeaderSize
	AnchorOffsetAdd  = "A2:offset+length"
	AnchorCursorAdd  = "A3:cursor+length"
)

const (
	recordHeaderSize = 9 // tag(1) + length(4) + offset(4)
	maxPayload       = 1 << 20
	maxRecordCount   = 1 << 16
)

var (
	ErrEmpty        = errors.New("empty input")
	ErrTruncated    = errors.New("truncated frame")
	ErrBadMagic     = errors.New("bad magic")
	ErrCountTooBig  = errors.New("record count exceeds cap")
	ErrLengthTooBig = errors.New("payload length exceeds cap")
	ErrOverflow     = errors.New("integer overflow detected")
)

// Record is one decoded entry. Offset is the raw on-wire offset.
type Record struct {
	Index  int    `json:"index"`
	Tag    byte   `json:"tag"`
	Length uint32 `json:"length"`
	Offset uint32 `json:"offset"`
	// PayloadOffset is the absolute cursor where the payload starts.
	PayloadOffset uint32 `json:"payload_offset"`
}

// Frame is the result of a successful parse.
type Frame struct {
	RecordCount uint32   `json:"record_count"`
	Records     []Record `json:"records"`
	Consumed    int      `json:"consumed"`
}

// WrapEvidence captures the concrete wrapped result of one unsafe anchor,
// demonstrating what the vulnerable arithmetic actually produced.
type WrapEvidence struct {
	Anchor  string `json:"anchor"`
	A       uint32 `json:"a"`
	B       uint32 `json:"b"`
	Wrapped uint32 `json:"wrapped"`
	Cursor  uint32 `json:"cursor"`
}

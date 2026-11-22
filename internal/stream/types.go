// Package stream defines the truncated compressed-stream wire format and
// its deterministic parser. A stream is a sequence of self describing frames:
//
//	magic(4) | frame... | EOF marker(1)
//
// Each frame:
//
//	type(1) | flags(1) | deviceID(uvarint) | seq(uvarint) |
//	tsMillis(uvarint) | payloadLen(uvarint) | payload(payloadLen)
//
// Payload bytes are flate-compressed JSON of a repeated observation of the
// same logical object. Real captures may end abruptly (power loss, buffer
// truncation); the parser must classify every failure mode instead of
// crashing.
package stream

import "errors"

// FrameType discriminates control frames from data frames.
type FrameType uint8

const (
	TypeData FrameType = 0x01
	TypeEOF  FrameType = 0x7E
)

// Frame flags.
const (
	FlagCompressed uint8 = 0x01
	FlagCheckpoint uint8 = 0x02
)

var magic = [4]byte{'T', 'S', 'T', '1'}

// Record is one decoded repeated-object observation emitted by a device.
type Record struct {
	DeviceID uint32 `json:"device_id"`
	Seq      uint64 `json:"seq"`
	TsMillis int64  `json:"ts_millis"`
	ObjectID string `json:"object_id"`
	Metric   int64  `json:"metric"`
	Quality  uint8  `json:"quality"`
}

// Frame is one parsed wire frame plus its decode status.
type Frame struct {
	Type     FrameType
	Flags    uint8
	Record   Record
	Payload  []byte
	Offset   int64
	EndOff   int64
	Checksum uint32
}

// Truncation failure classes. They are stable strings because they are
// persisted as evidence and checked by independent reviewers.
const (
	ErrClassMagic       = "BAD_MAGIC"
	ErrClassHeader      = "TRUNCATED_HEADER"
	ErrClassLength      = "TRUNCATED_PAYLOAD"
	ErrClassChecksum    = "CHECKSUM_MISMATCH"
	ErrClassCompression = "DECOMPRESS_FAILED"
	ErrClassEncoding    = "BAD_JSON_ENCODING"
	ErrClassUnknownType = "UNKNOWN_FRAME_TYPE"
)

// ParseError carries a machine readable class and the byte offset at which
// parsing stopped.
type ParseError struct {
	Class  string
	Offset int64
	Detail string
}

func (e *ParseError) Error() string {
	return e.Class + " at offset " + itoa(e.Offset) + ": " + e.Detail
}

// Is lets errors.Is match on class without allocating sentinel errors.
func (e *ParseError) Is(target error) bool {
	t, ok := target.(*ParseError)
	return ok && t.Class == e.Class
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ErrEmpty is returned when an input contains no frames at all.
var ErrEmpty = errors.New("stream contains no data frame")

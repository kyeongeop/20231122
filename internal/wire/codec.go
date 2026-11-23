package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	Magic                 = "DFB1"
	Version          byte = 1
	MaxInput              = 4096
	MaxRecords            = 16
	MaxPayload            = 512
	HeaderSize            = 8
	RecordHeaderSize      = 4
	TrailerSize           = 4
)

var crcTable = crc32.MakeTable(crc32.IEEE)

type Error struct {
	Code   string
	Offset int
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s at offset %d", e.Code, e.Offset)
	}
	return fmt.Sprintf("%s at offset %d: %s", e.Code, e.Offset, e.Detail)
}

func fail(code string, offset int, detail string) error {
	return &Error{Code: code, Offset: offset, Detail: detail}
}

type Record struct {
	ID      uint16 `json:"id"`
	Payload string `json:"payload"`
}

type Envelope struct {
	Records []Record `json:"records"`
}

func Parse(data []byte) (Envelope, error) {
	var out Envelope
	if len(data) > MaxInput {
		return out, fail("too_large", 0, fmt.Sprintf("input is %d bytes, limit is %d", len(data), MaxInput))
	}
	if len(data) < HeaderSize+RecordHeaderSize+1+TrailerSize {
		return out, fail("too_short", 0, "frame is shorter than the minimum valid size")
	}
	if string(data[:4]) != Magic {
		return out, fail("bad_magic", 0, "expected DFB1")
	}
	if data[4] != Version {
		return out, fail("bad_version", 4, fmt.Sprintf("got %d, want %d", data[4], Version))
	}
	count := int(data[5])
	if count < 1 || count > MaxRecords {
		return out, fail("bad_count", 5, fmt.Sprintf("got %d, allowed 1..%d", count, MaxRecords))
	}
	flags := binary.BigEndian.Uint16(data[6:8])
	if flags != 0 {
		return out, fail("bad_flags", 6, fmt.Sprintf("got 0x%04x, want 0", flags))
	}

	bodyEnd := len(data) - TrailerSize
	pos := HeaderSize
	seen := make(map[uint16]struct{}, count)
	records := make([]Record, 0, count)
	for i := 0; i < count; i++ {
		if pos+RecordHeaderSize > bodyEnd {
			return out, fail("truncated_record", pos, fmt.Sprintf("record %d header is incomplete", i))
		}
		id := binary.BigEndian.Uint16(data[pos : pos+2])
		length := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += RecordHeaderSize
		if id == 0 {
			return out, fail("zero_id", pos-4, fmt.Sprintf("record %d has id 0", i))
		}
		if length < 1 || length > MaxPayload {
			return out, fail("bad_payload_length", pos-2, fmt.Sprintf("record %d length is %d, allowed 1..%d", i, length, MaxPayload))
		}
		if pos+length > bodyEnd {
			return out, fail("truncated_payload", pos, fmt.Sprintf("record %d declares %d bytes", i, length))
		}
		if _, exists := seen[id]; exists {
			return out, fail("duplicate_id", pos-4, fmt.Sprintf("record id %d appears more than once", id))
		}
		seen[id] = struct{}{}
		payload := string(data[pos : pos+length])
		if !utf8.ValidString(payload) {
			return out, fail("invalid_utf8", pos, fmt.Sprintf("record %d payload is not UTF-8", i))
		}
		if strings.ContainsRune(payload, '\x00') {
			return out, fail("nul_payload", pos, fmt.Sprintf("record %d payload contains NUL", i))
		}
		records = append(records, Record{ID: id, Payload: payload})
		pos += length
	}
	if pos != bodyEnd {
		return out, fail("trailing_bytes", pos, fmt.Sprintf("%d bytes remain before checksum", bodyEnd-pos))
	}
	wantCRC := binary.BigEndian.Uint32(data[bodyEnd:])
	gotCRC := crc32.Checksum(data[:bodyEnd], crcTable)
	if gotCRC != wantCRC {
		return out, fail("bad_crc", bodyEnd, fmt.Sprintf("got 0x%08x, want 0x%08x", gotCRC, wantCRC))
	}

	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	out.Records = records
	return out, nil
}

func Encode(env Envelope) ([]byte, error) {
	if len(env.Records) < 1 || len(env.Records) > MaxRecords {
		return nil, fail("bad_count", 5, fmt.Sprintf("got %d, allowed 1..%d", len(env.Records), MaxRecords))
	}
	size := HeaderSize + TrailerSize
	seen := make(map[uint16]struct{}, len(env.Records))
	for _, rec := range env.Records {
		if rec.ID == 0 {
			return nil, fail("zero_id", 0, "record id must be non-zero")
		}
		if _, exists := seen[rec.ID]; exists {
			return nil, fail("duplicate_id", 0, fmt.Sprintf("record id %d appears more than once", rec.ID))
		}
		seen[rec.ID] = struct{}{}
		if len(rec.Payload) < 1 || len(rec.Payload) > MaxPayload {
			return nil, fail("bad_payload_length", 0, fmt.Sprintf("record %d length is %d", rec.ID, len(rec.Payload)))
		}
		if !utf8.ValidString(rec.Payload) || strings.ContainsRune(rec.Payload, '\x00') {
			return nil, fail("bad_payload", 0, fmt.Sprintf("record %d payload is invalid", rec.ID))
		}
		size += RecordHeaderSize + len(rec.Payload)
	}
	if size > MaxInput {
		return nil, fail("too_large", 0, fmt.Sprintf("encoded frame is %d bytes", size))
	}

	buf := make([]byte, size)
	copy(buf[:4], Magic)
	buf[4] = Version
	buf[5] = byte(len(env.Records))
	pos := HeaderSize
	for _, rec := range env.Records {
		binary.BigEndian.PutUint16(buf[pos:pos+2], rec.ID)
		binary.BigEndian.PutUint16(buf[pos+2:pos+4], uint16(len(rec.Payload)))
		pos += RecordHeaderSize
		copy(buf[pos:], rec.Payload)
		pos += len(rec.Payload)
	}
	binary.BigEndian.PutUint32(buf[pos:], crc32.Checksum(buf[:pos], crcTable))
	return buf, nil
}

func CanonicalDigest(records []Record) string {
	sorted := append([]Record(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	h := sha256.New()
	var header [4]byte
	for _, rec := range sorted {
		binary.BigEndian.PutUint16(header[:2], rec.ID)
		binary.BigEndian.PutUint16(header[2:], uint16(len(rec.Payload)))
		h.Write(header[:])
		h.Write([]byte(rec.Payload))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Classify(err error) string {
	if err == nil {
		return "valid"
	}
	var boundaryErr *Error
	if errors.As(err, &boundaryErr) {
		return "invalid:" + boundaryErr.Code
	}
	return "internal_error"
}

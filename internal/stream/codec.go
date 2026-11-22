package stream

// This file replaces codec.go; the old file is kept only until the parser
// rewrite is verified, then removed.

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
)

// EncodeOptions controls how BuildStream serializes frames.
type EncodeOptions struct {
	Compress bool
	// TruncateAt >= 0 cuts the output at that many bytes, simulating an
	// abrupt capture truncation. -1 disables truncation.
	TruncateAt int
	// OmitEOF skips the terminal EOF marker.
	OmitEOF bool
	// CorruptSeq flips one byte inside the payload of the frame carrying
	// that seq value (nil disables corruption).
	CorruptSeq *uint64
}

func appendUvarint(b []byte, v uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	return append(b, buf[:n]...)
}

// BuildStream serializes records into the on-wire format. Every third frame
// is marked as a checkpoint (safe suspend boundary).
func BuildStream(records []Record, opt EncodeOptions) ([]byte, error) {
	if opt.TruncateAt == 0 {
		opt.TruncateAt = -1
	}
	out := make([]byte, 0, 64)
	out = append(out, magic[:]...)
	for idx, rec := range records {
		raw, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		payload := raw
		flags := uint8(0)
		if opt.Compress {
			var zbuf bytes.Buffer
			zw, err := flate.NewWriter(&zbuf, flate.DefaultCompression)
			if err != nil {
				return nil, err
			}
			if _, err := zw.Write(raw); err != nil {
				return nil, err
			}
			if err := zw.Close(); err != nil {
				return nil, err
			}
			payload = zbuf.Bytes()
			flags |= FlagCompressed
		}
		if idx%3 == 0 {
			flags |= FlagCheckpoint
		}
		if opt.CorruptSeq != nil && rec.Seq == *opt.CorruptSeq && len(payload) > 0 {
			payload = append([]byte(nil), payload...)
			payload[0] ^= 0xFF
		}
		body := []byte{byte(TypeData), flags}
		body = appendUvarint(body, uint64(rec.DeviceID))
		body = appendUvarint(body, rec.Seq)
		body = appendUvarint(body, uint64(rec.TsMillis))
		body = appendUvarint(body, uint64(len(payload)))
		body = append(body, payload...)
		out = appendUvarint(out, uint64(crc32.ChecksumIEEE(body)))
		out = append(out, body...)
	}
	if !opt.OmitEOF {
		out = append(out, byte(TypeEOF))
	}
	if opt.TruncateAt >= 0 && opt.TruncateAt < len(out) {
		out = out[:opt.TruncateAt]
	}
	return out, nil
}

// ParseResult is everything the parser observed, including the point at
// which a truncated stream stopped.
type ParseResult struct {
	Frames        []Frame
	SawEOF        bool
	BytesConsumed int64
	TotalBytes    int64
	Error         *ParseError
}

// Parse decodes a captured stream. It never panics on malformed input:
// truncated or corrupt captures return a ParseResult with Error set and all
// frames decoded before the failure fully populated.
//
// Wire layout per frame:
//
//	crc32(uvarint) | type(1) | flags(1) | deviceID(uvarint) | seq(uvarint)
//	| tsMillis(uvarint) | payloadLen(uvarint) | payload
//
// The checksum covers every byte from type through the final payload byte.
func Parse(data []byte) ParseResult {
	res := ParseResult{TotalBytes: int64(len(data))}
	if len(data) < len(magic) {
		res.Error = &ParseError{Class: ErrClassHeader, Offset: 0, Detail: "input shorter than magic"}
		return res
	}
	if !bytes.Equal(data[:4], magic[:]) {
		res.Error = &ParseError{Class: ErrClassMagic, Offset: 0, Detail: "magic mismatch"}
		return res
	}
	off := int64(4)
	for off < int64(len(data)) {
		if data[off] == byte(TypeEOF) {
			res.SawEOF = true
			res.BytesConsumed = off + 1
			return res
		}
		frameStart := off
		csum, n := binary.Uvarint(data[off:])
		if n <= 0 {
			res.Error = &ParseError{Class: ErrClassHeader, Offset: off, Detail: "crc field"}
			res.BytesConsumed = off
			return res
		}
		off += int64(n)
		if off+2 > int64(len(data)) || FrameType(data[off]) != TypeData {
			res.Error = &ParseError{Class: ErrClassUnknownType, Offset: off, Detail: "frame type"}
			res.BytesConsumed = frameStart
			return res
		}
		hdrStart := off
		flags := data[off+1]
		off += 2
		var header [4]uint64
		for i := range header {
			v, k := binary.Uvarint(data[off:])
			if k <= 0 || off+int64(k) > int64(len(data)) {
				res.Error = &ParseError{Class: ErrClassHeader, Offset: off, Detail: "varint header truncated"}
				res.BytesConsumed = frameStart
				return res
			}
			header[i] = v
			off += int64(k)
		}
		plen64 := header[3]
		if plen64 > uint64(len(data)) {
			res.Error = &ParseError{Class: ErrClassLength, Offset: off, Detail: "payload length overflows capture"}
			res.BytesConsumed = frameStart
			return res
		}
		plen := int64(plen64)
		if plen < 0 || off > int64(len(data))-plen {
			res.Error = &ParseError{Class: ErrClassLength, Offset: off, Detail: "declared payload exceeds capture"}
			res.BytesConsumed = frameStart
			return res
		}
		payload := data[off : off+plen]
		frameEnd := off + plen
		if crc32.ChecksumIEEE(data[hdrStart:frameEnd]) != uint32(csum) {
			res.Error = &ParseError{Class: ErrClassChecksum, Offset: frameStart, Detail: "frame crc32 mismatch"}
			res.BytesConsumed = frameStart
			return res
		}
		rec, perr := decodeRecord(payload, flags)
		if perr != nil {
			perr.Offset = frameStart
			res.Error = perr
			res.BytesConsumed = frameStart
			return res
		}
		res.Frames = append(res.Frames, Frame{
			Type:     TypeData,
			Flags:    flags,
			Record:   rec,
			Payload:  append([]byte(nil), payload...),
			Offset:   frameStart,
			EndOff:   frameEnd,
			Checksum: uint32(csum),
		})
		off = frameEnd
	}
	res.BytesConsumed = off
	if !res.SawEOF {
		res.Error = &ParseError{Class: ErrClassLength, Offset: off, Detail: "capture ended without EOF marker"}
	}
	return res
}

func decodeRecord(payload []byte, flags uint8) (Record, *ParseError) {
	raw := payload
	if flags&FlagCompressed != 0 {
		zr := flate.NewReader(bytes.NewReader(payload))
		decoded, err := io.ReadAll(zr)
		cerr := zr.Close()
		if err != nil {
			return Record{}, &ParseError{Class: ErrClassCompression, Detail: err.Error()}
		}
		if cerr != nil {
			return Record{}, &ParseError{Class: ErrClassCompression, Detail: cerr.Error()}
		}
		raw = decoded
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, &ParseError{Class: ErrClassEncoding, Detail: err.Error()}
	}
	return rec, nil
}

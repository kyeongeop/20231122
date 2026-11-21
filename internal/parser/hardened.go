package parser

import "math"

// add32 returns false when a+b would wrap the uint32 range.
func add32(a, b uint32) (uint32, bool) {
	if b > math.MaxUint32-a {
		return 0, false
	}
	return a + b, true
}

// mul32 returns false when a*b would wrap the uint32 range.
func mul32(a, b uint32) (uint32, bool) {
	if a != 0 && b > math.MaxUint32/a {
		return 0, false
	}
	return a * b, true
}

// ParseHardened applies explicit overflow guards at every anchor that the
// vulnerable version left unchecked, plus bounds validation before any slice
// indexing. It is the audited, accepted implementation.
func ParseHardened(data []byte) (*Frame, *ParseState, error) {
	if len(data) == 0 {
		return nil, nil, ErrEmpty
	}
	if len(data) < len(Magic) {
		return nil, nil, ErrTruncated
	}
	var magic [4]byte
	copy(magic[:], data[:4])
	if magic != Magic {
		return nil, nil, ErrBadMagic
	}
	if len(data) < 8 {
		return nil, nil, ErrTruncated
	}

	state := NewParseState(len(data))
	recordCount := le32(data[4:8])
	if recordCount > maxRecordCount {
		return nil, state, ErrCountTooBig
	}

	// Anchor A1 guarded.
	state.mark(AnchorCountScale, state.Cursor)
	tableWidth, ok := mul32(recordCount, recordHeaderSize)
	if !ok {
		return nil, state, ErrOverflow
	}
	// Records start at a fixed offset immediately after the 8-byte prefix;
	// tableWidth is validated separately to catch the A1 scaling overflow.
	if uint64(len(Magic))+4+uint64(tableWidth) > uint64(len(data)) {
		return nil, state, ErrOverflow
	}
	cursor := uint32(len(Magic) + 4)

	frame := &Frame{RecordCount: recordCount, Records: make([]Record, 0, recordCount)}
	for index := uint32(0); index < recordCount; index++ {
		if uint64(cursor)+recordHeaderSize > uint64(len(data)) {
			return frame, state, ErrTruncated
		}
		head := data[cursor:]
		tag := head[0]
		length := le32(head[1:5])
		offset := le32(head[5:9])

		// Anchor A2 guarded.
		state.mark(AnchorOffsetAdd, cursor)
		end, ok := add32(offset, length)
		if !ok {
			return frame, state, ErrOverflow
		}

		// Anchor A3 guarded.
		state.mark(AnchorCursorAdd, cursor)
		payloadAt, ok := add32(cursor, length)
		if !ok {
			return frame, state, ErrOverflow
		}

		frame.Records = append(frame.Records, Record{
			Index:         int(index),
			Tag:           tag,
			Length:        length,
			Offset:        offset,
			PayloadOffset: payloadAt,
		})
		if uint64(payloadAt) > uint64(len(data)) {
			return frame, state, ErrTruncated
		}
		cursor = end
	}
	frame.Consumed = int(cursor)
	return frame, state, nil
}

package parser

// ParseVulnerable mirrors the historical parser that used unchecked uint32
// arithmetic. It is retained so the fuzzer can demonstrate the overflow and
// so the audit has a reproducible "before" implementation.
//
// The three overflow anchors are marked exactly where the unsafe math happens.
func ParseVulnerable(data []byte) (*Frame, *ParseState, error) {
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

	// Anchor A1: width of the whole header table in bytes.
	state.mark(AnchorCountScale, state.Cursor)
	tableWidth := recordCount * recordHeaderSize // overflow #1
	if recordCount != 0 && tableWidth/recordHeaderSize != recordCount {
		state.Wraps = append(state.Wraps, WrapEvidence{
			Anchor: AnchorCountScale, A: recordCount, B: recordHeaderSize,
			Wrapped: tableWidth, Cursor: state.Cursor,
		})
	}

	// Records begin at the fixed offset after the 8-byte prefix. The unsafe
	// tableWidth above is retained only as overflow evidence.
	cursor := uint32(len(Magic) + 4)
	frame := &Frame{RecordCount: recordCount, Records: make([]Record, 0, recordCount%64)}

	for index := uint32(0); index < recordCount; index++ {
		if int(cursor)+recordHeaderSize > len(data) {
			return frame, state, ErrTruncated
		}
		head := data[cursor:]
		tag := head[0]
		length := le32(head[1:5])
		offset := le32(head[5:9])

		// Anchor A2: endpoint derived from attacker-controlled offset/length.
		state.mark(AnchorOffsetAdd, cursor)
		end := offset + length // overflow #2
		if length > ^uint32(0)-offset {
			state.Wraps = append(state.Wraps, WrapEvidence{
				Anchor: AnchorOffsetAdd, A: offset, B: length,
				Wrapped: end, Cursor: cursor,
			})
		}

		// Anchor A3: advancing the cursor by the claimed length.
		state.mark(AnchorCursorAdd, cursor)
		payloadAt := cursor + length // overflow #3
		if length > ^uint32(0)-cursor {
			state.Wraps = append(state.Wraps, WrapEvidence{
				Anchor: AnchorCursorAdd, A: cursor, B: length,
				Wrapped: payloadAt, Cursor: cursor,
			})
		}

		frame.Records = append(frame.Records, Record{
			Index:         int(index),
			Tag:           tag,
			Length:        length,
			Offset:        offset,
			PayloadOffset: payloadAt,
		})
		cursor = end
	}
	frame.Consumed = int(cursor)
	return frame, state, nil
}

package experiment

import (
	"encoding/binary"
	"hash/crc32"

	"example.com/deserialize-boundary/internal/wire"
)

func canonicalRecords() []wire.Record {
	return []wire.Record{
		{ID: 1, Payload: "alpha"},
		{ID: 2, Payload: "beta"},
		{ID: 3, Payload: "gamma"},
		{ID: 4, Payload: "delta"},
	}
}

func submitOps(records []wire.Record) []Op {
	ops := make([]Op, 0, len(records)+1)
	for _, rec := range records {
		copy := rec
		ops = append(ops, Op{Kind: OpSubmit, Label: "submit", Record: &copy})
	}
	return append(ops, Op{Kind: OpCommit, Label: "commit"})
}

func CoreScenarios() []Scenario {
	asc := submitOps(canonicalRecords())
	descRecords := canonicalRecords()
	for left, right := 0, len(descRecords)-1; left < right; left, right = left+1, right-1 {
		descRecords[left], descRecords[right] = descRecords[right], descRecords[left]
	}
	desc := submitOps(descRecords)

	cancelOps := []Op{
		{Kind: OpSubmit, Label: "submit-before-cancel-1", Record: &wire.Record{ID: 1, Payload: "alpha"}},
		{Kind: OpSubmit, Label: "submit-before-cancel-2", Record: &wire.Record{ID: 2, Payload: "beta"}},
		{Kind: OpCancel, Label: "midway-cancel", Reason: "cancel-after-two-accepted-records"},
		{Kind: OpSubmit, Label: "submit-after-cancel-1", Record: &wire.Record{ID: 3, Payload: "gamma"}},
		{Kind: OpSubmit, Label: "submit-after-cancel-2", Record: &wire.Record{ID: 4, Payload: "delta"}},
		{Kind: OpCommit, Label: "commit-after-cancel"},
	}
	controlOps := append([]Op(nil), cancelOps...)

	dupOps := []Op{
		{Kind: OpSubmit, Label: "first-id-1", Record: &wire.Record{ID: 1, Payload: "alpha"}},
		{Kind: OpSubmit, Label: "first-id-2", Record: &wire.Record{ID: 2, Payload: "beta"}},
		{Kind: OpSubmit, Label: "repeat-id-2", Record: &wire.Record{ID: 2, Payload: "beta"}},
		{Kind: OpSubmit, Label: "id-3", Record: &wire.Record{ID: 3, Payload: "gamma"}},
		{Kind: OpSubmit, Label: "id-4", Record: &wire.Record{ID: 4, Payload: "delta"}},
		{Kind: OpCommit, Label: "commit"},
	}

	ascFrame := frameHex(canonicalRecords())
	descFrame := frameHex(descRecords)
	dupFrame := duplicateIDFrame()
	truncFrame := ascFrame[:len(ascFrame)-2]
	return []Scenario{
		{
			ID:          "order-asc",
			Description: "commit four records in ascending id order",
			Role:        "baseline",
			Mode:        "commit",
			Expected:    "committed:4",
			Ops:         asc,
		},
		{
			ID:          "order-desc",
			Description: "commit the same four records in descending id order",
			Role:        "verification",
			Mode:        "commit",
			Expected:    "committed:4;digest-equals-order-asc",
			Ops:         desc,
		},
		{
			ID:          "cancel-target",
			Description: "cancel after two accepted records, then attempt two more submits and commit",
			Role:        "target",
			Mode:        "cancel",
			Expected:    "cancelled:0",
			Ops:         cancelOps,
		},
		{
			ID:          "cancel-control",
			Description: "repeat the same midpoint cancellation in an isolated control run",
			Role:        "control",
			Mode:        "cancel",
			Expected:    "cancelled:0",
			Ops:         controlOps,
		},
		{
			ID:          "duplicate-submit",
			Description: "submit id 2 twice before committing",
			Role:        "verification",
			Mode:        "commit",
			Expected:    "committed:4;duplicate=1",
			Ops:         dupOps,
		},
		{
			ID:          "parser-boundary",
			Description: "replay valid order variants and malformed frames through the Gowire parser",
			Role:        "verification",
			Mode:        "parse",
			Expected:    "order-equal;duplicate-id-rejected;truncation-rejected",
			Ops: []Op{
				{Kind: OpParseRaw, Label: "wire-order-asc", RawHex: rawHex(ascFrame), ExpectKind: "valid"},
				{Kind: OpParseRaw, Label: "wire-order-desc", RawHex: rawHex(descFrame), ExpectKind: "valid"},
				{Kind: OpParseRaw, Label: "wire-duplicate-id", RawHex: rawHex(dupFrame), ExpectKind: "invalid:duplicate_id"},
				{Kind: OpParseRaw, Label: "wire-truncated", RawHex: rawHex(truncFrame), ExpectKind: "invalid:truncated_payload"},
			},
		},
	}
}

func frameHex(records []wire.Record) []byte {
	frame, err := wire.Encode(wire.Envelope{Records: records})
	if err != nil {
		panic(err)
	}
	return frame
}

func duplicateIDFrame() []byte {
	frame, err := wire.Encode(wire.Envelope{Records: []wire.Record{
		{ID: 1, Payload: "alpha"},
		{ID: 2, Payload: "beta"},
	}})
	if err != nil {
		panic(err)
	}
	secondID := wire.HeaderSize + wire.RecordHeaderSize + len("alpha")
	binary.BigEndian.PutUint16(frame[secondID:secondID+2], 1)
	binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.Checksum(frame[:len(frame)-4], crc32.MakeTable(crc32.IEEE)))
	return frame
}

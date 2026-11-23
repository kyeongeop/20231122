package wire

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

func frame(records []Record) []byte {
	data, err := Encode(Envelope{Records: records})
	if err != nil {
		panic(err)
	}
	return data
}

func rawFrame(records []Record) []byte {
	size := HeaderSize + TrailerSize
	for _, rec := range records {
		size += RecordHeaderSize + len(rec.Payload)
	}
	data := make([]byte, size)
	copy(data[:4], Magic)
	data[4] = Version
	data[5] = byte(len(records))
	pos := HeaderSize
	for _, rec := range records {
		binary.BigEndian.PutUint16(data[pos:pos+2], rec.ID)
		binary.BigEndian.PutUint16(data[pos+2:pos+4], uint16(len(rec.Payload)))
		pos += RecordHeaderSize
		copy(data[pos:], rec.Payload)
		pos += len(rec.Payload)
	}
	binary.BigEndian.PutUint32(data[pos:], crc32.Checksum(data[:pos], crcTable))
	return data
}

func validRecords() []Record {
	return []Record{
		{ID: 1, Payload: "alpha"},
		{ID: 2, Payload: "beta"},
		{ID: 3, Payload: "gamma"},
		{ID: 4, Payload: "delta"},
	}
}

func TestOrderDoesNotChangeCanonicalResult(t *testing.T) {
	asc := frame(validRecords())
	desc := frame([]Record{
		{ID: 4, Payload: "delta"},
		{ID: 3, Payload: "gamma"},
		{ID: 2, Payload: "beta"},
		{ID: 1, Payload: "alpha"},
	})
	a, err := Parse(asc)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(desc)
	if err != nil {
		t.Fatal(err)
	}
	if CanonicalDigest(a.Records) != CanonicalDigest(d.Records) {
		t.Fatal("wire order changed the canonical digest")
	}
	if a.Records[0].ID != 1 || a.Records[3].ID != 4 {
		t.Fatalf("records were not canonicalized: %#v", a.Records)
	}
}

func TestDuplicateIDIsRejected(t *testing.T) {
	data := rawFrame([]Record{{ID: 1, Payload: "first"}, {ID: 1, Payload: "second"}})
	_, err := Parse(data)
	if err == nil || Classify(err) != "invalid:duplicate_id" {
		t.Fatalf("want duplicate_id, got %v", err)
	}
}

func TestBoundaryMatrix(t *testing.T) {
	base := frame(validRecords())
	cases := []struct {
		name string
		data []byte
		code string
	}{
		{"empty", nil, "too_short"},
		{"too_short", []byte("DFB1"), "too_short"},
		{"too_large", make([]byte, MaxInput+1), "too_large"},
		{"bad_magic", replaceBytes(base, 0, 'X'), "bad_magic"},
		{"bad_version", replaceBytes(base, 4, 2), "bad_version"},
		{"bad_flags", replaceBytes(base, 7, 1), "bad_flags"},
		{"bad_count_zero", replaceBytes(base, 5, 0), "bad_count"},
		{"bad_count_high", replaceBytes(base, 5, MaxRecords+1), "bad_count"},
		{"zero_id", fixRawCRC(replaceBytes(base, 9, 0)), "zero_id"},
		{"zero_payload", fixRawCRC(replaceBytes(base, 11, 0)), "bad_payload_length"},
		{"truncated_payload", base[:len(base)-2], "truncated_payload"},
		{"trailing", insertRaw(base, []byte{0x7f}), "trailing_bytes"},
		{"bad_crc", replaceBytes(base, len(base)-1, base[len(base)-1]^0xff), "bad_crc"},
		{"invalid_utf8", rawFrame([]Record{{ID: 5, Payload: string([]byte{0xff})}}), "invalid_utf8"},
		{"nul_payload", rawFrame([]Record{{ID: 5, Payload: "a\x00b"}}), "nul_payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			_, err := Parse(tc.data)
			if Classify(err) != "invalid:"+tc.code {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
		})
	}
}

func replaceBytes(data []byte, index int, value byte) []byte {
	out := append([]byte(nil), data...)
	out[index] = value
	return out
}

func fixRawCRC(data []byte) []byte {
	out := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(out[len(out)-4:], crc32.Checksum(out[:len(out)-4], crcTable))
	return out
}

func insertRaw(data, inserted []byte) []byte {
	out := append(append(append([]byte(nil), data[:len(data)-4]...), inserted...), data[len(data)-4:]...)
	return fixRawCRC(out)
}

func TestMutationalBoundaryNoPanic(t *testing.T) {
	base := frame(validRecords())
	for i := 0; i < len(base); i++ {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), base...)
			mutated[i] ^= 1 << bit
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("panic at byte %d bit %d: %v", i, bit, recovered)
					}
				}()
				_, _ = Parse(mutated)
			}()
		}
	}
	_, err := Parse(nil)
	var boundaryErr *Error
	if !errors.As(err, &boundaryErr) {
		t.Fatalf("nil input should return a typed boundary error, got %v", err)
	}
}

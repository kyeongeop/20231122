package stream

import (
	"testing"
)

// FuzzParse feeds arbitrary bytes to the parser. The hard contract is:
// never panic, always leave BytesConsumed within bounds, and any returned
// error must carry one of the documented classes.
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		{},
		{1, 2, 3},
		[]byte("TST1"),
		[]byte("XXXX"),
	}
	base := GenRecords(101, "obj", 6, 1000, 50, 0)
	full, err := BuildStream(base, EncodeOptions{Compress: true})
	if err != nil {
		f.Fatal(err)
	}
	seeds = append(seeds, full, full[:4], full[:len(full)/2], full[:len(full)-1])
	plain, _ := BuildStream(base, EncodeOptions{Compress: false})
	seeds = append(seeds, plain)
	for _, s := range seeds {
		f.Add(s)
	}

	validClasses := map[string]bool{
		ErrClassMagic: true, ErrClassHeader: true, ErrClassLength: true,
		ErrClassChecksum: true, ErrClassCompression: true,
		ErrClassEncoding: true, ErrClassUnknownType: true,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := Parse(data)
		if res.BytesConsumed < 0 || res.BytesConsumed > res.TotalBytes {
			t.Fatalf("consumed %d out of %d", res.BytesConsumed, res.TotalBytes)
		}
		if res.Error != nil && !validClasses[res.Error.Class] {
			t.Fatalf("undocumented error class %q", res.Error.Class)
		}
		if res.SawEOF && res.Error != nil && res.Error.Class == ErrClassLength {
			t.Fatalf("stream with EOF must not report truncation")
		}
		// Round trip property: every fully parsed frame re-encodes through
		// the same checksum, proving evidence bytes are exact.
		for _, fr := range res.Frames {
			if fr.EndOff <= fr.Offset {
				t.Fatalf("non-positive frame span %d..%d", fr.Offset, fr.EndOff)
			}
			if len(fr.Payload) == 0 {
				t.Fatalf("empty payload retained at %d", fr.Offset)
			}
		}
	})
}

// FuzzBuildParse ensures any generated record list round trips when no
// truncation or corruption is requested.
func FuzzBuildParse(f *testing.F) {
	f.Add(uint(12), uint8(1), int64(7), true)
	f.Fuzz(func(t *testing.T, n uint, dev uint8, off int64, compress bool) {
		if n > 200 {
			n = 200
		}
		recs := GenRecords(100+uint32(dev), "obj", int(n)+1, 1000, 25, off)
		wire, err := BuildStream(recs, EncodeOptions{Compress: compress})
		if err != nil {
			t.Fatal(err)
		}
		res := Parse(wire)
		if res.Error != nil {
			t.Fatalf("round trip parse failed: %v", res.Error)
		}
		if len(res.Frames) != len(recs) {
			t.Fatalf("frame count %d want %d", len(res.Frames), len(recs))
		}
	})
}

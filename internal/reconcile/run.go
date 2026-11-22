package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"truncstream/internal/stream"
)

// Fingerprint builds a stable hash of the exact parser-visible input: frame
// offsets, checksums and raw payload bytes. Two runs over the same capture
// must produce the same fingerprint even if processing is suspended.
func Fingerprint(a, b stream.ParseResult) string {
	h := sha256.New()
	write := func(r stream.ParseResult) {
		for _, f := range r.Frames {
			var lb [8]byte
			putUint64(lb[:], uint64(f.Offset))
			h.Write(lb[:])
			putUint64(lb[:], uint64(f.EndOff))
			h.Write(lb[:])
			putUint64(lb[:], uint64(f.Checksum))
			h.Write(lb[:])
			h.Write(f.Payload)
		}
		var b [1]byte
		if r.SawEOF {
			b[0] = 1
		}
		h.Write(b[:])
		if r.Error != nil {
			h.Write([]byte(r.Error.Class))
		}
	}
	write(a)
	write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// Run aligns two parsed feeds and produces a fully deterministic report.
// Records are matched on (object_id, seq). The reference timeline is device
// A; every reconciled timestamp equals raw_ms - device_offset_ms.
func Run(pa, pb stream.ParseResult) (Report, error) {
	ia, objA, err := index(pa.Frames)
	if err != nil {
		return Report{}, err
	}
	ib, objB, err := index(pb.Frames)
	if err != nil {
		return Report{}, err
	}
	if objA != "" && objB != "" && objA != objB {
		return Report{}, ErrMixedObjects
	}
	object := objA
	if object == "" {
		object = objB
	}
	offA, offB, err := EstimateOffsets(ia, ib)
	if err != nil {
		return Report{}, err
	}

	seqs := make(map[uint64]struct{})
	for k := range ia {
		seqs[k.seq] = struct{}{}
	}
	for k := range ib {
		seqs[k.seq] = struct{}{}
	}
	ordered := make([]uint64, 0, len(seqs))
	for s := range seqs {
		ordered = append(ordered, s)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	rep := Report{
		ObjectID:         object,
		DeviceAOffsetMs:  offA,
		DeviceBOffsetMs:  offB,
		InputFingerprint: Fingerprint(pa, pb),
	}
	for _, seq := range ordered {
		ka := key{object: object, seq: seq}
		ra, inA := ia[ka]
		rb, inB := ib[ka]
		switch {
		case inA && !inB:
			rep.OnlyA = append(rep.OnlyA, seq)
		case inB && !inA:
			rep.OnlyB = append(rep.OnlyB, seq)
		default:
			delta := (rb.TsMillis - offB) - (ra.TsMillis - offA)
			pair := Pair{
				ObjectID:     object,
				Seq:          seq,
				DeviceARawMs: ra.TsMillis,
				DeviceBRawMs: rb.TsMillis,
				RefMs:        ra.TsMillis - offA,
				DeltaMs:      delta,
				MetricA:      ra.Metric,
				MetricB:      rb.Metric,
				MetricMatch:  ra.Metric == rb.Metric,
				QualityA:     ra.Quality,
				QualityB:     rb.Quality,
			}
			rep.Pairs = append(rep.Pairs, pair)
			rep.MatchedCount++
			if !pair.MetricMatch {
				rep.MetricMismatches++
			}
		}
	}
	rep.PairCount = len(rep.Pairs)
	return rep, nil
}

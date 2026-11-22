// Package reconcile aligns repeated-object observations produced by two
// devices whose clocks are not synchronized. Matching is based on the
// monotonically increasing per-object sequence number, never on wall clock
// time. The clock offset of each device is estimated by robust median of
// paired timestamp differences.
package reconcile

import (
	"errors"
	"sort"

	"truncstream/internal/stream"
)

// Device IDs are fixed so a reviewer can reason about the two feeds.
const (
	DeviceA uint32 = 101
	DeviceB uint32 = 202
)

// Pair is one matched observation of the same object/sequence from the two
// devices, with both raw and reconciled timestamps.
type Pair struct {
	ObjectID     string `json:"object_id"`
	Seq          uint64 `json:"seq"`
	DeviceARawMs int64  `json:"device_a_raw_ms"`
	DeviceBRawMs int64  `json:"device_b_raw_ms"`
	RefMs        int64  `json:"reference_ms"`
	DeltaMs      int64  `json:"delta_ms"`
	MetricA      int64  `json:"metric_a"`
	MetricB      int64  `json:"metric_b"`
	MetricMatch  bool   `json:"metric_match"`
	QualityA     uint8  `json:"quality_a"`
	QualityB     uint8  `json:"quality_b"`
}

// Report is the deterministic output of one reconciliation run.
type Report struct {
	ObjectID         string   `json:"object_id"`
	DeviceAOffsetMs  int64    `json:"device_a_offset_ms"`
	DeviceBOffsetMs  int64    `json:"device_b_offset_ms"`
	PairCount        int      `json:"pair_count"`
	MatchedCount     int      `json:"matched_count"`
	MetricMismatches int      `json:"metric_mismatches"`
	OnlyA            []uint64 `json:"only_in_a"`
	OnlyB            []uint64 `json:"only_in_b"`
	Pairs            []Pair   `json:"pairs"`
	InputFingerprint string   `json:"input_fingerprint"`
}

var (
	// ErrNoCommonPoint means the two feeds share no (object, seq) key.
	ErrNoCommonPoint = errors.New("feeds share no observation point")
	// ErrMixedObjects means a feed contained more than one object id.
	ErrMixedObjects = errors.New("feed mixes multiple object ids")
)

type key struct {
	object string
	seq    uint64
}

// EstimateOffsets returns the median (raw - reference) offset per device.
// Device A defines the reference timeline, so its offset is computed against
// itself and is always zero; B's offset is the median clock skew relative to
// A. Median (not mean) makes the estimate robust to a handful of bad points.
func EstimateOffsets(a, b map[key]stream.Record) (int64, int64, error) {
	keys := make([]key, 0, len(a))
	for k := range a {
		if _, ok := b[k]; !ok {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return 0, 0, ErrNoCommonPoint
	}
	// Map iteration order is randomized; sort shared keys so the median
	// skew estimate never depends on Go's map traversal order.
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].object != keys[j].object {
			return keys[i].object < keys[j].object
		}
		return keys[i].seq < keys[j].seq
	})
	deltas := make([]int64, 0, len(keys))
	for _, k := range keys {
		deltas = append(deltas, b[k].TsMillis-a[k].TsMillis)
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i] < deltas[j] })
	return 0, deltas[len(deltas)/2], nil
}

func index(frames []stream.Frame) (map[key]stream.Record, string, error) {
	out := make(map[key]stream.Record, len(frames))
	object := ""
	for _, f := range frames {
		r := f.Record
		if object == "" {
			object = r.ObjectID
		} else if r.ObjectID != object {
			return nil, "", ErrMixedObjects
		}
		out[key{object: r.ObjectID, seq: r.Seq}] = r
	}
	return out, object, nil
}

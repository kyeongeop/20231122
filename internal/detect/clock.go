package detect

import (
	"fmt"
	"sort"

	"idorfix/internal/domain"
)

// RuleVersion identifies the detection logic. Any rule change bumps this so
// that exported evidence always states which logic produced the verdict.
const RuleVersion = "rules-2026.11.0"

// NormalizeClocks moves every event onto the reference timeline by removing
// the calibrated per-device offset. It returns the adjusted events plus any
// missing fragments implied by residual clock uncertainty.
//
// A missing fragment is the union of uncertainty windows around events whose
// ordering across two differently-clocked devices cannot be established.
func NormalizeClocks(s *domain.Sample) ([]domain.EvidenceEvent, []domain.MissingFragment, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil sample")
	}
	clockByDevice := make(map[string]domain.DeviceClock, len(s.Clocks))
	for _, c := range s.Clocks {
		if c.DeviceID == "" {
			return nil, nil, fmt.Errorf("clock entry with empty device_id")
		}
		clockByDevice[c.DeviceID] = c
	}

	events := make([]domain.EvidenceEvent, len(s.Events))
	copy(events, s.Events)
	for i := range events {
		clock, ok := clockByDevice[events[i].DeviceID]
		if !ok {
			return nil, nil, fmt.Errorf("event %s references unknown device %q", events[i].EventID, events[i].DeviceID)
		}
		// adjusted = raw - offset, because offset = device - reference.
		events[i].AdjustedNS = events[i].RawTime.UnixNano() - clock.OffsetNS
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].AdjustedNS != events[j].AdjustedNS {
			return events[i].AdjustedNS < events[j].AdjustedNS
		}
		return events[i].Seq < events[j].Seq
	})

	fragments := buildMissingFragments(events, clockByDevice)
	return events, fragments, nil
}

// buildMissingFragments walks adjacent events from different devices. When the
// gap between them is smaller than the sum of their residual uncertainties,
// their true ordering is unknowable: that interval is a missing fragment.
func buildMissingFragments(events []domain.EvidenceEvent, clocks map[string]domain.DeviceClock) []domain.MissingFragment {
	type interval struct{ start, end int64 }
	var raw []interval

	for i := 0; i+1 < len(events); i++ {
		left, right := events[i], events[i+1]
		if left.DeviceID == right.DeviceID {
			continue
		}
		leftUncertainty := clocks[left.DeviceID].UncertaintyNS
		rightUncertainty := clocks[right.DeviceID].UncertaintyNS
		// Uncertainty extends on both sides of the adjusted point.
		leftWindowEnd := left.AdjustedNS + leftUncertainty
		rightWindowStart := right.AdjustedNS - rightUncertainty
		if rightWindowStart <= leftWindowEnd {
			start := left.AdjustedNS - leftUncertainty
			end := right.AdjustedNS + rightUncertainty
			if end > start {
				raw = append(raw, interval{start: start, end: end})
			}
		}
	}

	if len(raw) == 0 {
		return nil
	}
	sort.Slice(raw, func(i, j int) bool { return raw[i].start < raw[j].start })

	// Merge overlapping intervals so evidence stays compact and stable.
	merged := []interval{raw[0]}
	for _, next := range raw[1:] {
		last := &merged[len(merged)-1]
		if next.start <= last.end {
			if next.end > last.end {
				last.end = next.end
			}
			continue
		}
		merged = append(merged, next)
	}

	fragments := make([]domain.MissingFragment, 0, len(merged))
	for idx, gap := range merged {
		anchor := nearestEvent(events, (gap.start+gap.end)/2)
		fragments = append(fragments, domain.MissingFragment{
			FragmentID:    fmt.Sprintf("MF-%03d", idx+1),
			StartNS:       gap.start,
			EndNS:         gap.end,
			AnchorEventID: anchor,
			Reason:        "cross-device ordering unresolvable within residual clock uncertainty",
		})
	}
	return fragments
}

func nearestEvent(events []domain.EvidenceEvent, target int64) string {
	best := ""
	var bestDistance int64 = 1<<63 - 1
	for _, event := range events {
		distance := event.AdjustedNS - target
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			bestDistance = distance
			best = event.EventID
		}
	}
	return best
}

// InsideFragment reports whether an adjusted timestamp falls inside any gap.
func InsideFragment(fragments []domain.MissingFragment, adjustedNS int64) (string, bool) {
	for _, fragment := range fragments {
		if adjustedNS >= fragment.StartNS && adjustedNS <= fragment.EndNS {
			return fragment.FragmentID, true
		}
	}
	return "", false
}

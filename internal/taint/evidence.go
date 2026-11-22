package taint

import (
	"fmt"
	"time"

	"taintlab/internal/canonical"
	"taintlab/internal/model"
)

func buildEvidence(
	result model.Result,
	scenario model.Scenario,
	diagnostics diagnosticList,
) (model.Evidence, diagnosticList) {
	evidence := model.Evidence{
		Events: []model.LogEvent{},
		Key:    []model.EvidencePointer{},
	}
	aWall, aOK := parseClock(scenario.Clocks.DeviceA.WallTime)
	bWall, bOK := parseClock(scenario.Clocks.DeviceB.WallTime)
	if !aOK {
		diagnostics.add("warning", "invalid_device_a_clock",
			"device_a.wall_time is not RFC3339; its raw value is retained")
	}
	if !bOK {
		diagnostics.add("warning", "invalid_device_b_clock",
			"device_b.wall_time is not RFC3339; its raw value is retained")
	}

	deviceA := scenario.Clocks.DeviceA.DeviceID
	if deviceA == "" {
		deviceA = "device-a"
	}
	deviceB := scenario.Clocks.DeviceB.DeviceID
	if deviceB == "" {
		deviceB = "device-b"
	}

	attackPayload := canonical.Sum(struct {
		Source     model.Source      `json:"source"`
		Operations []model.Operation `json:"operations"`
		Boundary   model.Boundary    `json:"boundary"`
		Permission model.Permission  `json:"permission"`
	}{
		Source:     scenario.Source,
		Operations: scenario.Operations,
		Boundary:   scenario.Boundary,
		Permission: scenario.Permission,
	})
	attackWall := clockText(aWall, aOK, scenario.Clocks.DeviceA.WallTime, 0)
	triggerWall := clockText(bWall, bOK, scenario.Clocks.DeviceB.WallTime, 5*time.Millisecond)
	permissionWall := clockText(bWall, bOK, scenario.Clocks.DeviceB.WallTime, 6*time.Millisecond)
	sealWall := clockText(bWall, bOK, scenario.Clocks.DeviceB.WallTime, 7*time.Millisecond)

	events := []model.LogEvent{
		{
			Ordinal:       1,
			EventID:       result.TraceID + "-e01",
			DeviceID:      deviceA,
			Kind:          "attack_input",
			CausalOrder:   1,
			WallTime:      attackWall,
			MonotonicNS:   scenario.Clocks.DeviceA.MonotonicNS,
			PayloadSHA256: attackPayload,
			Detail: fmt.Sprintf("source=%q value=%d tainted=%t operations=%d boundary=[%d,%d]",
				scenario.Source.Label, scenario.Source.Value, scenario.Source.Tainted,
				len(scenario.Operations), scenario.Boundary.Min, scenario.Boundary.Max),
		},
		{
			Ordinal:       2,
			EventID:       result.TraceID + "-e02",
			DeviceID:      deviceB,
			Kind:          "trigger_location",
			CausalOrder:   2,
			WallTime:      triggerWall,
			MonotonicNS:   scenario.Clocks.DeviceB.MonotonicNS + int64(5*time.Millisecond),
			PayloadSHA256: canonical.Sum(result.Trigger),
			Detail: fmt.Sprintf("detected=%t seq=%d location=%s before=%d after=%d width=%d",
				result.Trigger.Detected, result.Trigger.OperationSeq, result.Trigger.Location,
				result.Trigger.Before, result.Trigger.After, result.Trigger.WidthBits),
		},
		{
			Ordinal:       3,
			EventID:       result.TraceID + "-e03",
			DeviceID:      deviceB,
			Kind:          "permission_decision",
			CausalOrder:   3,
			WallTime:      permissionWall,
			MonotonicNS:   scenario.Clocks.DeviceB.MonotonicNS + int64(6*time.Millisecond),
			PayloadSHA256: canonical.Sum(result.Permission),
			Detail: fmt.Sprintf("policy=%s required=%d baseline=%s effective=%s mismatch=%t escalation=%t",
				result.Permission.Policy, result.Permission.RequiredToken,
				result.Permission.BaselineDecision, result.Permission.EffectiveDecision,
				result.Permission.Mismatch, result.Permission.TaintedEscalation),
		},
	}
	firstHashes := []string{events[0].PayloadSHA256, events[1].PayloadSHA256, events[2].PayloadSHA256}
	sealPayload := canonical.Sum(struct {
		Previous []string `json:"previous"`
	}{
		Previous: firstHashes,
	})
	events = append(events, model.LogEvent{
		Ordinal:       4,
		EventID:       result.TraceID + "-e04",
		DeviceID:      deviceB,
		Kind:          "log_evidence",
		CausalOrder:   4,
		WallTime:      sealWall,
		MonotonicNS:   scenario.Clocks.DeviceB.MonotonicNS + int64(7*time.Millisecond),
		PayloadSHA256: sealPayload,
		Detail:        "four causal events sealed; wall clocks are not used for ordering",
	})

	evidence.Clock = detectClockAnomaly(scenario, aWall, aOK, bWall, bOK)
	evidence.Events = events
	evidence.Key = append(evidence.Key, model.EvidencePointer{
		Kind:   "input",
		Ref:    "sha256:" + result.Input.SHA256,
		SHA256: result.Input.SHA256,
		Note:   fmt.Sprintf("accepted JSON input, %d bytes", result.Input.SizeBytes),
	})
	for _, event := range events {
		evidence.Key = append(evidence.Key, model.EvidencePointer{
			Kind:   "event",
			Ref:    event.EventID,
			SHA256: event.PayloadSHA256,
			Note:   event.Kind + " on " + event.DeviceID,
		})
	}
	if evidence.Clock.Detected {
		evidence.Key = append(evidence.Key, model.EvidencePointer{
			Kind:   "clock_anomaly",
			Ref:    "clock:" + deviceA + "->" + deviceB,
			SHA256: canonical.Sum(evidence.Clock),
			Note:   evidence.Clock.Reason,
		})
	}

	eventHashes := make([]string, 0, len(events))
	for _, event := range events {
		eventHashes = append(eventHashes, event.PayloadSHA256)
	}
	evidence.SHA256 = canonical.Sum(struct {
		InputSHA    string                 `json:"input_sha256"`
		Trigger     model.Trigger          `json:"trigger"`
		Permission  model.PermissionResult `json:"permission"`
		Clock       model.ClockAnomaly     `json:"clock_anomaly"`
		EventHashes []string               `json:"event_hashes"`
	}{
		InputSHA:    result.Input.SHA256,
		Trigger:     result.Trigger,
		Permission:  result.Permission,
		Clock:       evidence.Clock,
		EventHashes: eventHashes,
	})
	return evidence, diagnostics
}

func parseClock(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func clockText(parsed time.Time, ok bool, raw string, delta time.Duration) string {
	if !ok {
		return raw
	}
	return parsed.Add(delta).Format(time.RFC3339Nano)
}

func detectClockAnomaly(
	scenario model.Scenario,
	aWall time.Time,
	aOK bool,
	bWall time.Time,
	bOK bool,
) model.ClockAnomaly {
	threshold := scenario.Clocks.MaxSkewMS
	if threshold <= 0 {
		threshold = 1000
	}
	anomaly := model.ClockAnomaly{
		ThresholdMS: threshold,
		Reason:      "clock_not_compared",
	}
	if !aOK || !bOK {
		return anomaly
	}
	anomaly.SkewMS = bWall.Sub(aWall).Milliseconds()
	anomaly.WallRegression = anomaly.SkewMS < 0
	switch {
	case anomaly.WallRegression:
		anomaly.Detected = true
		anomaly.Reason = "negative_wall_delta_across_devices"
	case abs64(anomaly.SkewMS) > threshold:
		anomaly.Detected = true
		anomaly.Reason = "wall_clock_skew_exceeds_threshold"
	default:
		anomaly.Reason = "clocks_within_tolerance"
	}
	return anomaly
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

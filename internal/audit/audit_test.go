package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"auditfix/internal/audit"
)

type testLogEvent struct {
	Seq           int64  `json:"seq"`
	Device        string `json:"device"`
	TimeUnixNS    int64  `json:"time_unix_ns"`
	Kind          string `json:"kind"`
	AnchorID      string `json:"anchor_id"`
	Subject       string `json:"subject"`
	PayloadSHA256 string `json:"payload_sha256"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

func TestHashEventKnownValue(t *testing.T) {
	zero := strings.Repeat("0", 64)
	got := audit.HashEvent("device-a", 1, 1_000_000_000, "anchor",
		"beacon-1", "clock.sync", zero, zero)
	const want = "c78f429d18ca4f93c009359803d6eec9d6563e024896cac2ffef4f67b767a934"
	if got != want {
		t.Fatalf("hash mismatch: got %s want %s", got, want)
	}
}

func TestAnalyzeClockSkewAndMissingSegment(t *testing.T) {
	base := int64(1_763_772_000_000_000_000)
	logA := buildDeviceLog(t, "device-a", base, 0,
		map[int64]bool{3: true, 4: true})
	logB := buildDeviceLog(t, "device-b", base, 10*time.Second, nil)
	eventsA, err := audit.ParseDeviceLog(bytes.NewReader(logA), "device-a")
	if err != nil {
		t.Fatal(err)
	}
	eventsB, err := audit.ParseDeviceLog(bytes.NewReader(logB), "device-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsA) != 3 || len(eventsB) != 5 {
		t.Fatalf("unexpected event counts: %d %d", len(eventsA), len(eventsB))
	}
	if eventsA[2].ChainRelation != "gap_sealed" {
		t.Fatalf("visible gap relation: %s", eventsA[2].ChainRelation)
	}
	result := audit.Analyze(eventsA, eventsB, "case-1", "2026-01-01T00:00:00Z")
	if result.ClockOffsetNS != int64(10*time.Second) {
		t.Fatalf("clock offset: %d", result.ClockOffsetNS)
	}
	if result.AnchorPairs != 2 {
		t.Fatalf("anchor pairs: %d", result.AnchorPairs)
	}
	if len(result.Corrections) != 1 {
		t.Fatalf("corrections: %d", len(result.Corrections))
	}
	correction := result.Corrections[0]
	if correction.Device != "device-a" || correction.SeqFrom != 3 ||
		correction.SeqTo != 4 || correction.MissingCount != 2 {
		t.Fatalf("unexpected correction: %+v", correction)
	}
	if result.ChainStatus != "visible_gap" || result.Status != "needs_review" {
		t.Fatalf("unexpected status: %s / %s", result.ChainStatus, result.Status)
	}
	for _, event := range result.Events {
		if event.Device == "device-b" && event.CorrectedNS != event.TimeUnixNS-int64(10*time.Second) {
			t.Fatalf("device-b event was not corrected")
		}
	}
}

func TestParseRejectsTamperedRecordHash(t *testing.T) {
	data := buildDeviceLog(t, "device-a", 1_763_772_000_000_000_000, 0, nil)
	var source []testLogEvent
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var event testLogEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		source = append(source, event)
	}
	source[0].RecordHash = strings.Repeat("f", 64)
	var tampered bytes.Buffer
	for _, event := range source {
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		tampered.Write(line)
		tampered.WriteByte('\n')
	}
	events, err := audit.ParseDeviceLog(bytes.NewReader(tampered.Bytes()), "device-a")
	if err != nil {
		t.Fatal(err)
	}
	if events[0].HashValid {
		t.Fatal("tampered event hash was accepted")
	}
	result := audit.Analyze(events, events, "case-1", "2026-01-01T00:00:00Z")
	if result.ChainStatus != "broken_hash" {
		t.Fatalf("chain status: %s", result.ChainStatus)
	}
}

func TestParseRejectsOutOfOrderSequence(t *testing.T) {
	base := int64(1_763_772_000_000_000_000)
	first := eventAt("device-a", 1, base, strings.Repeat("0", 64))
	second := eventAt("device-a", 2, base+1e9, first.RecordHash)
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(second)
	_ = encoder.Encode(first)
	if _, err := audit.ParseDeviceLog(bytes.NewReader(data.Bytes()), "device-a"); err == nil {
		t.Fatal("out-of-order sequence was accepted")
	}
}

func buildDeviceLog(t *testing.T, device string, base int64, skew time.Duration,
	skip map[int64]bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	last := strings.Repeat("0", 64)
	for seq := int64(1); seq <= 5; seq++ {
		if skip[seq] {
			continue
		}
		event := eventAt(device, seq, base+seq*int64(time.Second)+int64(skew), last)
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
		last = event.RecordHash
	}
	return buf.Bytes()
}

func eventAt(device string, seq, timeNS int64, prev string) testLogEvent {
	kind, anchor, subject := "operation", "", "auth.verify"
	payload := digest(fmt.Sprintf("%s:%d", device, seq))
	if seq == 1 || seq == 5 {
		kind, anchor, subject = "anchor", "beacon-test", "clock.sync"
		payload = digest("beacon:beacon-test")
	}
	return testLogEvent{
		Seq: seq, Device: device, TimeUnixNS: timeNS, Kind: kind,
		AnchorID: anchor, Subject: subject, PayloadSHA256: payload,
		PrevHash: prev,
		RecordHash: audit.HashEvent(device, seq, timeNS, kind, anchor,
			subject, payload, prev),
	}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

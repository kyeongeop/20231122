package pipeline

import (
	"encoding/json"
	"os"

	"example.com/replay-review/internal/model"
)

const fixtureBase = int64(1_700_000_000_000)

// Fixture builds the canonical two-device scenario:
//
//	dev-a is disciplined to the reference clock (offset 0).
//	dev-b's local clock runs 120s behind (offset +120000 to recover reference).
//	dev-a is missing sequences 3 and 4 (the missing fragment).
//	dev-b exhibits a reference-clock jump above the configured threshold.
//	The stream contains one legitimate replay, one expiry, one unknown code
//	and one clock-desync consume-before-issue.
func Fixture(cfg model.Config) InputFile {
	events := []model.Event{
		{Sequence: 1, DeviceID: "dev-a", Code: "C-1001", UserID: "u1",
			Kind: model.KindIssue, ObservedAt: fixtureBase, OffsetMs: 0},
		{Sequence: 2, DeviceID: "dev-b", Code: "C-1001", UserID: "u1",
			Kind:       model.KindConsume,
			ObservedAt: fixtureBase + 30_000 - 120_000, OffsetMs: 120_000},
		// dev-a sequences 3..4 are absent: the missing fragment.
		{Sequence: 4, DeviceID: "dev-b", Code: "C-1002", UserID: "u2",
			Kind:       model.KindIssue,
			ObservedAt: fixtureBase + 40_000 - 120_000, OffsetMs: 120_000},
		{Sequence: 5, DeviceID: "dev-a", Code: "C-1001", UserID: "u1",
			Kind: model.KindConsume, ObservedAt: fixtureBase + 60_000, OffsetMs: 0},
		// dev-b jump from reference +40s to +90s (50s) trips the clock gap.
		{Sequence: 6, DeviceID: "dev-b", Code: "C-1002", UserID: "u2",
			Kind:       model.KindConsume,
			ObservedAt: fixtureBase + 90_000 - 120_000, OffsetMs: 120_000},
		{Sequence: 7, DeviceID: "dev-a", Code: "C-1002", UserID: "u2",
			Kind: model.KindConsume, ObservedAt: fixtureBase + 400_000, OffsetMs: 0},
		{Sequence: 8, DeviceID: "dev-b", Code: "C-9999", UserID: "u9",
			Kind:       model.KindConsume,
			ObservedAt: fixtureBase + 100_000 - 120_000, OffsetMs: 120_000},
		{Sequence: 9, DeviceID: "dev-a", Code: "C-2000", UserID: "u3",
			Kind: model.KindConsume, ObservedAt: fixtureBase + 20_000, OffsetMs: 0},
		{Sequence: 10, DeviceID: "dev-b", Code: "C-2000", UserID: "u3",
			Kind: model.KindIssue,
			// Arrives later in the stream; dev-b's skewed clock disciplines
			// its reference time 40s after the consume (negative-age desync).
			ObservedAt: fixtureBase + 60_000 - 120_000, OffsetMs: 120_000},
	}
	return InputFile{
		StreamID: "stream-fixture-001",
		Config:   &cfg,
		Events:   events,
	}
}

// WriteFixture renders the fixture as a checked-in reviewable JSON file.
func WriteFixture(path string, cfg model.Config) error {
	in := Fixture(cfg)
	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

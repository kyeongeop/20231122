package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"auditfix/internal/model"
)

const clockSkewWarningNS int64 = 1_000_000

type Result struct {
	ClockOffsetNS int64
	AnchorPairs   int
	ChainStatus   string
	Status        string
	Events        []model.Event
	Corrections   []model.Correction
	Warnings      []string
}

type anchorPair struct {
	ID     string
	A      model.Event
	B      model.Event
	Offset int64
}

func Analyze(aEvents, bEvents []model.Event, caseID, createdAt string) Result {
	result := Result{}
	result.Events = append(result.Events, aEvents...)
	result.Events = append(result.Events, bEvents...)

	pairs, mismatch := matchAnchors(aEvents, bEvents)
	result.AnchorPairs = len(pairs)
	if len(pairs) > 0 {
		result.ClockOffsetNS = medianOffset(pairs)
	}
	for i := range result.Events {
		if result.Events[i].Device == "device-b" {
			result.Events[i].CorrectedNS = result.Events[i].TimeUnixNS - result.ClockOffsetNS
		}
	}

	for device, events := range map[string][]model.Event{
		"device-a": aEvents,
		"device-b": bEvents,
	} {
		corrections := findGaps(device, events, caseID, createdAt, result.AnchorPairs)
		result.Corrections = append(result.Corrections, corrections...)
	}
	sort.Slice(result.Corrections, func(i, j int) bool {
		if result.Corrections[i].Device != result.Corrections[j].Device {
			return result.Corrections[i].Device < result.Corrections[j].Device
		}
		return result.Corrections[i].SeqFrom < result.Corrections[j].SeqFrom
	})

	result.ChainStatus = chainStatus(aEvents, bEvents, mismatch)
	result.Status = "verified"
	if mismatch {
		result.Warnings = append(result.Warnings, "shared anchor payload mismatch")
	}
	if len(result.Corrections) > 0 {
		result.Status = "needs_review"
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%d missing segment(s) annotated; original records were not fabricated",
			len(result.Corrections)))
	}
	if abs64(result.ClockOffsetNS) >= clockSkewWarningNS {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("clock skew %d ns corrected using shared anchors", result.ClockOffsetNS))
	}
	return result
}

func matchAnchors(aEvents, bEvents []model.Event) ([]anchorPair, bool) {
	aAnchors := make(map[string][]model.Event)
	bAnchors := make(map[string][]model.Event)
	for _, event := range aEvents {
		if event.Kind == "anchor" {
			aAnchors[event.AnchorID] = append(aAnchors[event.AnchorID], event)
		}
	}
	for _, event := range bEvents {
		if event.Kind == "anchor" {
			bAnchors[event.AnchorID] = append(bAnchors[event.AnchorID], event)
		}
	}
	ids := make([]string, 0, len(aAnchors))
	for id := range aAnchors {
		if len(bAnchors[id]) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var pairs []anchorPair
	mismatch := false
	for _, id := range ids {
		aList, bList := aAnchors[id], bAnchors[id]
		n := len(aList)
		if len(bList) < n {
			n = len(bList)
		}
		for i := 0; i < n; i++ {
			if aList[i].PayloadSHA256 != bList[i].PayloadSHA256 ||
				aList[i].Subject != bList[i].Subject {
				mismatch = true
				continue
			}
			pairs = append(pairs, anchorPair{
				ID:     id,
				A:      aList[i],
				B:      bList[i],
				Offset: bList[i].TimeUnixNS - aList[i].TimeUnixNS,
			})
		}
	}
	return pairs, mismatch
}

func medianOffset(pairs []anchorPair) int64 {
	offsets := make([]int64, 0, len(pairs))
	for _, pair := range pairs {
		offsets = append(offsets, pair.Offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	mid := len(offsets) / 2
	if len(offsets)%2 == 1 {
		return offsets[mid]
	}
	return (offsets[mid-1] + offsets[mid]) / 2
}

func findGaps(device string, events []model.Event, caseID, createdAt string,
	anchorPairs int) []model.Correction {
	var corrections []model.Correction
	for i := 1; i < len(events); i++ {
		left, right := events[i-1], events[i]
		if right.Seq <= left.Seq+1 {
			continue
		}
		from, to := left.Seq+1, right.Seq-1
		rationale := "sequence_gap_with_visible_hash_boundaries"
		if right.ChainRelation == "gap_unresolved" {
			rationale = "sequence_gap_prev_hash_unresolved"
		}
		seed := caseID + "|" + device + "|" + strconv.FormatInt(from, 10) + "|" + strconv.FormatInt(to, 10)
		sum := sha256.Sum256([]byte(seed))
		corrections = append(corrections, model.Correction{
			CorrectionID:      "corr-" + hex.EncodeToString(sum[:6]),
			CaseID:            caseID,
			Device:            device,
			SeqFrom:           from,
			SeqTo:             to,
			MissingCount:      to - from + 1,
			LeftSeq:           left.Seq,
			LeftHash:          left.RecordHash,
			RightSeq:          right.Seq,
			RightPrevHash:     right.PrevHash,
			CorrectedTimeFrom: left.CorrectedNS,
			CorrectedTimeTo:   right.CorrectedNS,
			AnchorPairsUsed:   anchorPairs,
			RationaleCode:     rationale,
			Status:            "open",
			CreatedAt:         createdAt,
		})
	}
	return corrections
}

func chainStatus(aEvents, bEvents []model.Event, anchorMismatch bool) string {
	status := "verified"
	if anchorMismatch {
		status = "anchor_mismatch"
	}
	for _, events := range [][]model.Event{aEvents, bEvents} {
		for _, event := range events {
			if !event.HashValid {
				return "broken_hash"
			}
			if event.ChainRelation == "broken_prev_hash" ||
				event.ChainRelation == "gap_unresolved" {
				status = "broken_or_unresolved"
			}
			if event.ChainRelation == "gap_sealed" && status == "verified" {
				status = "visible_gap"
			}
		}
	}
	return status
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func Summary(r Result) string {
	var b strings.Builder
	b.WriteString("clock_offset_ns=")
	b.WriteString(strconv.FormatInt(r.ClockOffsetNS, 10))
	b.WriteString(" anchor_pairs=")
	b.WriteString(strconv.Itoa(r.AnchorPairs))
	b.WriteString(" chain=")
	b.WriteString(r.ChainStatus)
	for _, corr := range r.Corrections {
		b.WriteString(" gap=")
		b.WriteString(corr.Device)
		b.WriteString(":")
		b.WriteString(strconv.FormatInt(corr.SeqFrom, 10))
		b.WriteString("-")
		b.WriteString(strconv.FormatInt(corr.SeqTo, 10))
	}
	return b.String()
}

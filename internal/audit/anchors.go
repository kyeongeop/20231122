package audit

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type AnchorSet struct {
	Anchors  []Anchor
	Fallback bool
	Reason   string
}

func ResolveAnchors(data []byte, clock func() time.Time) AnchorSet {
	now := FormatTime(NowUTC(clock))
	explicit, sawMarker := explicitAnchors(data, now)
	if len(explicit) == 3 &&
		explicit[0].Offset < explicit[1].Offset &&
		explicit[1].Offset <= explicit[2].Offset &&
		explicit[2].Offset <= int64(len(data)) {
		return AnchorSet{Anchors: explicit}
	}

	first := lineStartAtOrAfter(data, int64(len(data))/3)
	second := lineStartAtOrAfter(data, int64(len(data))*2/3)
	if second < first {
		second = first
	}
	if first < 0 {
		first = 0
	}
	if second < 0 {
		second = first
	}
	anchors := []Anchor{
		{Number: 1, Label: "auto-third-1", Offset: first, Line: lineAt(data, first), CapturedAt: now},
		{Number: 2, Label: "auto-third-2", Offset: second, Line: lineAt(data, second), CapturedAt: now},
		{Number: 3, Label: "auto-eof", Offset: int64(len(data)), Line: lineAt(data, int64(len(data))), CapturedAt: now},
	}
	reason := "three usable explicit anchor markers were not found; synthesized thirds"
	if sawMarker {
		reason = "explicit anchor markers were incomplete or out of order; synthesized thirds"
	}
	return AnchorSet{Anchors: anchors, Fallback: true, Reason: reason}
}

func explicitAnchors(data []byte, now string) ([]Anchor, bool) {
	found := map[int]Anchor{}
	sawMarker := false
	forEachLine(data, func(lineNo int, start, end int64, raw []byte) bool {
		text := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(text, "#@anchor") {
			return true
		}
		sawMarker = true
		fields := strings.Fields(text)
		if len(fields) < 2 {
			return true
		}
		number, err := strconv.Atoi(fields[1])
		if err != nil || number < 1 || number > 3 {
			return true
		}
		anchor := Anchor{
			Number:     number,
			Label:      fmt.Sprintf("anchor-%d", number),
			Offset:     start,
			Line:       lineNo,
			CapturedAt: now,
			Explicit:   true,
		}
		for _, field := range fields[2:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch key {
			case "label":
				if value != "" {
					anchor.Label = value
				}
			case "captured_at":
				if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
					anchor.CapturedAt = FormatTime(parsed)
				}
			case "offset":
				if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
					anchor.DeclaredOffset = parsed
				}
			}
		}
		found[number] = anchor
		return true
	})
	anchors := make([]Anchor, 0, 3)
	for number := 1; number <= 3; number++ {
		anchor, ok := found[number]
		if !ok {
			return anchors, sawMarker
		}
		anchors = append(anchors, anchor)
	}
	return anchors, sawMarker
}

func lineStartAtOrAfter(data []byte, threshold int64) int64 {
	if threshold <= 0 {
		return 0
	}
	if threshold >= int64(len(data)) {
		return int64(len(data))
	}
	index := bytes.IndexByte(data[threshold:], '\n')
	if index < 0 {
		return int64(len(data))
	}
	return threshold + int64(index) + 1
}

func lineAt(data []byte, offset int64) int {
	if offset < 0 {
		return 1
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	return 1 + bytes.Count(data[:offset], []byte{'\n'})
}

func forEachLine(data []byte, visit func(lineNo int, start, end int64, raw []byte) bool) {
	var start int64
	lineNo := 1
	for start < int64(len(data)) {
		remaining := data[start:]
		index := bytes.IndexByte(remaining, '\n')
		end := int64(len(data))
		next := end
		if index >= 0 {
			end = start + int64(index)
			next = end + 1
		}
		rawEnd := end
		if rawEnd > start && data[rawEnd-1] == '\r' {
			rawEnd--
		}
		if !visit(lineNo, start, rawEnd, data[start:rawEnd]) {
			return
		}
		start = next
		lineNo++
	}
	if len(data) == 0 {
		return
	}
}

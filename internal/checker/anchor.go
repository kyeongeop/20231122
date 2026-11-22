package checker

import (
	"fmt"
	"strings"
)

// splitAnchors locates the three anchor markers in raw and returns the
// Anchor records with their zero-based byte offsets and segment bodies.
// Missing anchors are returned as findings rather than fatal errors so the
// caller can keep partial evidence and still emit a verdict.
func splitAnchors(raw string) ([]Anchor, []Finding) {
	markers := []string{Anchor1, Anchor2, Anchor3}
	anchors := make([]Anchor, 0, 3)
	var findings []Finding

	cursor := 0
	for idx, marker := range markers {
		rel := strings.Index(raw[cursor:], marker)
		if rel < 0 {
			findings = append(findings, Finding{
				Anchor:     marker,
				Offset:     cursor,
				ByteOffset: cursor,
				Stage:      "anchor",
				Code:       "anchor_missing",
				Message:    fmt.Sprintf("anchor marker %s not found in raw input", marker),
			})
			continue
		}
		off := cursor + rel
		bodyStart := off + len(marker)
		bodyEnd := len(raw)
		if idx+1 < len(markers) {
			if next := strings.Index(raw[bodyStart:], markers[idx+1]); next >= 0 {
				bodyEnd = bodyStart + next
			}
		}
		anchors = append(anchors, Anchor{
			Marker:    marker,
			Offset:    off,
			BodyStart: bodyStart,
			BodyEnd:   bodyEnd,
			Body:      strings.TrimSpace(raw[bodyStart:bodyEnd]),
		})
		cursor = bodyStart
	}
	return anchors, findings
}

// parseCase turns the three anchor bodies into a structured case.
//
//	ANCHOR1 -> DNS name (dotted text)
//	ANCHOR2 -> encoded labels, comma separated (e.g. punycode "xn--" labels)
//	ANCHOR3 -> comparison rule keyword (exact | case-insensitive | idna)
func parseCase(anchors []Anchor) (Case, Finding, bool) {
	var c Case
	byMarker := map[string]string{}
	for _, a := range anchors {
		byMarker[a.Marker] = a.Body
	}

	name, ok1 := byMarker[Anchor1]
	labelsRaw, ok2 := byMarker[Anchor2]
	rule, ok3 := byMarker[Anchor3]
	if !ok1 || !ok2 || !ok3 {
		return c, Finding{Offset: -1, ByteOffset: -1, Stage: "parse", Code: "case_incomplete",
			Message: "case requires all three anchor segments"}, false
	}

	c.DNSName = name
	for _, label := range strings.Split(labelsRaw, ",") {
		if label = strings.TrimSpace(label); label != "" {
			c.EncodedLabels = append(c.EncodedLabels, label)
		}
	}
	c.ComparisonRule = strings.ToLower(strings.TrimSpace(rule))
	return c, Finding{}, true
}

// anchorOffset returns the raw offset of the given marker, or -1.
func anchorOffset(anchors []Anchor, marker string) int {
	for _, a := range anchors {
		if a.Marker == marker {
			return a.Offset
		}
	}
	return -1
}

// bodyOffset maps a position inside an (already trimmed) anchor body to its
// absolute raw offset inside raw.
func bodyOffset(raw string, anchors []Anchor, marker string, bodyPos int) int {
	for _, a := range anchors {
		if a.Marker == marker {
			segment := raw[a.BodyStart:a.BodyEnd]
			trimLeft := len(segment) - len(strings.TrimLeft(segment, " \t\r\n"))
			return a.BodyStart + trimLeft + bodyPos
		}
	}
	return -1
}

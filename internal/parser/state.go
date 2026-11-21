package parser

import "time"

// ParseState tracks the cursor while walking a frame. It is created fresh per
// input and never shared between goroutines.
type ParseState struct {
	Cursor    uint32
	Remaining uint32
	// AnchorHits records the first cursor at which each anchor was evaluated.
	AnchorHits map[string]uint32
	// Wraps records the concrete wrapped results at unsafe anchors.
	Wraps     []WrapEvidence
	StartedAt time.Time
}

// NewParseState returns a state positioned at the first byte after magic.
func NewParseState(inputLen int) *ParseState {
	return &ParseState{
		Cursor:     uint32(len(Magic)),
		Remaining:  uint32(inputLen) - uint32(len(Magic)),
		AnchorHits: map[string]uint32{},
		Wraps:      []WrapEvidence{},
		StartedAt:  time.Now().UTC(),
	}
}

func (s *ParseState) mark(anchor string, cursor uint32) {
	if _, seen := s.AnchorHits[anchor]; !seen {
		s.AnchorHits[anchor] = cursor
	}
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

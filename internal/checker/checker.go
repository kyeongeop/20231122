// Package checker reconstructs the "DNS name encoding validation" pipeline.
//
// An input case carries three pieces of information:
//   - the DNS name under test (attack input),
//   - the encoded label set it is compared against,
//   - the comparison rule that decides whether the names are equivalent.
//
// Every case is built from three anchor markers (ANCHOR1/ANCHOR2/ANCHOR3).
// The anchor at which validation fails (the trigger position), the
// permission verdict (allow / deny / undetermined) and the retained log
// evidence are all reported together with the original byte offsets.
package checker

import (
	"crypto/sha256"
	"encoding/hex"
)

// Anchor markers split one raw case into its three segments.
const (
	Anchor1 = "ANCHOR1"
	Anchor2 = "ANCHOR2"
	Anchor3 = "ANCHOR3"
)

// Verdict is the permission decision for one case.
type Verdict string

const (
	// VerdictDeny: the anomaly was caught at a validation anchor; access is denied.
	VerdictDeny Verdict = "deny"
	// VerdictAllow: all three anchors passed validation; the name is accepted.
	VerdictAllow Verdict = "allow"
	// VerdictUndetermined: empty / oversized / malformed input cannot be judged.
	VerdictUndetermined Verdict = "undetermined"
)

// Hard limits taken from the DNS wire-format constraints (RFC 1035).
const (
	MaxNameLength  = 253 // dotted text form, excluding the trailing root label
	MaxLabelLength = 63  // single label length octet
	MaxInputBytes  = 1 << 16
)

// Step is one recorded processing stage in the lineage chain.
type Step struct {
	Name   string
	Detail string
}

// Anchor records one marker, its raw offset and the segment that follows it.
type Anchor struct {
	Marker    string
	Offset    int    // zero-based byte offset of the marker in the raw input
	BodyStart int    // absolute offset of the first byte after the marker
	BodyEnd   int    // absolute offset of the first byte of the next marker (or len(raw))
	Body      string // bytes between this marker and the next one (trimmed)
}

// Finding describes one validation failure.
type Finding struct {
	Anchor     string // anchor whose segment triggered the failure
	Offset     int    // raw byte offset of the offending byte/label
	ByteOffset int    // raw byte offset of the offending byte inside the anchor body
	Stage      string // pipeline stage name
	Code       string // machine-readable failure code
	Message    string // human-readable description
}

// Result is the full evaluation output for one raw input.
type Result struct {
	Verdict   Verdict
	Rationale string
	Anchors   []Anchor
	Findings  []Finding
	Steps     []Step
	// Evidence holds the key artifacts retained for audit, in particular for
	// undetermined edge cases (empty / oversized inputs).
	Evidence map[string]string
}

// Case is the parsed form: DNS name, encoded labels and comparison rule.
type Case struct {
	DNSName        string
	EncodedLabels  []string
	ComparisonRule string
}

// Digest returns the SHA-256 of the original raw bytes: the stable anchor
// every stored conclusion traces back to.
func Digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

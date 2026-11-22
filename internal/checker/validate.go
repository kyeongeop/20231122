package checker

import (
	"fmt"
	"strings"
)

// validateName checks the ANCHOR1 segment: the DNS name in dotted text form.
// Offset holds the anchor marker position (trigger position); ByteOffset
// holds the absolute raw offset of the offending byte inside the segment.
func validateName(raw string, anchors []Anchor, name string) []Finding {
	var out []Finding
	markerOff := anchorOffset(anchors, Anchor1)
	base := bodyOffset(raw, anchors, Anchor1, 0)
	if base < 0 {
		base = 0
	}

	if len(name) > MaxNameLength {
		out = append(out, Finding{Anchor: Anchor1, Offset: markerOff, ByteOffset: base + MaxNameLength,
			Stage: "validate_name", Code: "NAME_TOO_LONG",
			Message: fmt.Sprintf("dotted name is %d bytes, RFC 1035 limit is %d", len(name), MaxNameLength)})
	}

	pos := 0
	labels := strings.Split(name, ".")
	for idx, label := range labels {
		if label == "" {
			out = append(out, Finding{Anchor: Anchor1, Offset: markerOff, ByteOffset: base + pos,
				Stage: "validate_name", Code: "EMPTY_LABEL",
				Message: "empty label (leading dot, trailing dot or repeated dot)"})
			pos++
			continue
		}
		if len(label) > MaxLabelLength {
			out = append(out, Finding{Anchor: Anchor1, Offset: markerOff, ByteOffset: base + pos + MaxLabelLength,
				Stage: "validate_name", Code: "LABEL_TOO_LONG",
				Message: fmt.Sprintf("label %q is %d bytes, label length octet limit is %d",
					label, len(label), MaxLabelLength)})
		}
		for off, b := range []byte(label) {
			code, msg := classifyLabelByte(b)
			if code != "" {
				out = append(out, Finding{Anchor: Anchor1, Offset: markerOff, ByteOffset: base + pos + off,
					Stage: "validate_name", Code: code, Message: msg})
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			out = append(out, Finding{Anchor: Anchor1, Offset: markerOff, ByteOffset: base + pos,
				Stage: "validate_name", Code: "LABEL_HYPHEN_BOUNDARY",
				Message: "labels must not start or end with a hyphen"})
		}
		pos += len(label)
		if idx < len(labels)-1 {
			pos++ // the separating dot
		}
	}
	return out
}

func classifyLabelByte(b byte) (code, msg string) {
	switch {
	case b > 127:
		return "NON_ASCII_IN_WIRE_NAME",
			fmt.Sprintf("non-ASCII byte 0x%02x must be IDNA/punycode encoded before wire use", b)
	case b == '_':
		return "ILLEGAL_CHARACTER", "underscore is not legal in a host name label (LDH rule)"
	case b == ' ' || b < 0x21 || b == 0x7f:
		return "CONTROL_OR_WHITESPACE",
			fmt.Sprintf("control/whitespace byte 0x%02x is not legal in a label", b)
	case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '-':
		return "", ""
	default:
		return "ILLEGAL_CHARACTER",
			fmt.Sprintf("byte 0x%02x violates the letter-digit-hyphen rule", b)
	}
}

// validateEncoded checks the ANCHOR2 segment: the encoded label set.
func validateEncoded(raw string, anchors []Anchor, c Case) []Finding {
	var out []Finding
	markerOff := anchorOffset(anchors, Anchor2)
	base := bodyOffset(raw, anchors, Anchor2, 0)
	if base < 0 {
		base = 0
	}

	nameLabels := strings.Split(c.DNSName, ".")
	if len(c.EncodedLabels) != 0 && len(c.EncodedLabels) != len(nameLabels) {
		out = append(out, Finding{Anchor: Anchor2, Offset: markerOff, ByteOffset: base,
			Stage: "validate_encoded", Code: "LABEL_COUNT_MISMATCH",
			Message: fmt.Sprintf("DNS name has %d labels but encoded set has %d",
				len(nameLabels), len(c.EncodedLabels))})
	}

	pos := 0
	for idx, label := range c.EncodedLabels {
		if len(label) > MaxLabelLength {
			out = append(out, Finding{Anchor: Anchor2, Offset: markerOff, ByteOffset: base + pos + MaxLabelLength,
				Stage: "validate_encoded", Code: "ENCODED_LABEL_TOO_LONG",
				Message: fmt.Sprintf("encoded label %q is %d bytes, limit is %d",
					label, len(label), MaxLabelLength)})
		}
		nameHasHigh := idx < len(nameLabels) && containsHighByte(nameLabels[idx])
		if nameHasHigh && !strings.HasPrefix(strings.ToLower(label), "xn--") {
			out = append(out, Finding{Anchor: Anchor2, Offset: markerOff, ByteOffset: base + pos,
				Stage: "validate_encoded", Code: "ENCODING_MISMATCH",
				Message: fmt.Sprintf("non-ASCII label %q requires a punycode (xn--) encoded counterpart",
					nameLabels[idx])})
		}
		for off, b := range []byte(label) {
			if !isLDH(b) {
				out = append(out, Finding{Anchor: Anchor2, Offset: markerOff, ByteOffset: base + pos + off,
					Stage: "validate_encoded", Code: "ILLEGAL_ENCODED_CHAR",
					Message: fmt.Sprintf("encoded label contains non-LDH byte 0x%02x", b)})
				break
			}
		}
		pos += len(label)
		if idx < len(c.EncodedLabels)-1 {
			pos++ // separating comma
		}
	}
	return out
}

func isLDH(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '-'
}

func containsHighByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return true
		}
	}
	return false
}

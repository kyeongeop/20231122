package checker

import (
	"fmt"
	"strings"
)

// knownRules are the accepted ANCHOR3 comparison-rule keywords.
var knownRules = map[string]bool{
	"exact":            true,
	"case-insensitive": true,
	"idna":             true,
}

// validateRule checks the ANCHOR3 segment and performs the actual comparison.
func validateRule(raw string, anchors []Anchor, c Case) []Finding {
	var out []Finding
	base := bodyOffset(raw, anchors, Anchor3, 0)
	if base < 0 {
		base = 0
	}
	if !knownRules[c.ComparisonRule] {
		out = append(out, Finding{Anchor: Anchor3, Offset: anchorOffset(anchors, Anchor3), ByteOffset: base,
			Stage: "validate_rule", Code: "UNKNOWN_RULE",
			Message: fmt.Sprintf("comparison rule %q is not one of exact/case-insensitive/idna",
				c.ComparisonRule)})
		return out
	}

	// Re-encode the DNS name per the rule and compare against the encoded label set.
	want := encodeForComparison(c.DNSName, c.ComparisonRule)
	got := strings.Join(c.EncodedLabels, ".")
	if c.ComparisonRule == "idna" {
		want = idnaProjection(c)
	}
	if want != got {
		out = append(out, Finding{Anchor: Anchor3, Offset: anchorOffset(anchors, Anchor3), ByteOffset: base,
			Stage: "compare", Code: "COMPARISON_FAILED",
			Message: fmt.Sprintf("rule %s: re-encoded name %q != supplied encoded labels %q",
				c.ComparisonRule, want, got)})
	}
	return out
}

// encodeForComparison models the exact and case-insensitive rules:
//
//	exact            -> labels joined as-is
//	case-insensitive -> lower-cased ASCII labels joined
//	idna             -> handled separately by idnaProjection
func encodeForComparison(name, rule string) string {
	labels := strings.Split(name, ".")
	for i, label := range labels {
		switch rule {
		case "exact":
			// unchanged
		case "case-insensitive":
			labels[i] = strings.ToLower(label)
		case "idna":
			labels[i] = strings.ToLower(label)
		}
	}
	return strings.Join(labels, ".")
}

// idnaProjection maps the DNS name to the label set a conforming IDNA
// encoder is expected to produce: ASCII labels are lower-cased; high-byte
// labels must appear as the supplied xn-- punycode label at the same index.
func idnaProjection(c Case) string {
	nameLabels := strings.Split(c.DNSName, ".")
	parts := make([]string, len(nameLabels))
	for i, label := range nameLabels {
		switch {
		case containsHighByte(label):
			if i < len(c.EncodedLabels) {
				parts[i] = strings.ToLower(c.EncodedLabels[i])
			} else {
				parts[i] = "xn--"
			}
		default:
			parts[i] = strings.ToLower(label)
		}
	}
	return strings.Join(parts, ".")
}

// Evaluate runs the reconstructed pipeline on one raw input and returns the
// full result: anchor map, trigger position, permission verdict and evidence.
func Evaluate(raw string) Result {
	res := Result{Evidence: map[string]string{}}

	// Edge case 1: empty input. Nothing can be parsed; retain the empty body
	// as evidence and return undetermined rather than guessing a verdict.
	if len(raw) == 0 {
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：空输入，缺少三段锚点，无法解析 DNS 名称/编码标签/比较规则"
		res.Steps = []Step{{Name: "guard", Detail: "raw input is 0 bytes"}}
		res.Evidence["raw_hex"] = ""
		res.Evidence["raw_len"] = "0"
		return res
	}

	// Edge case 2: oversized input. Keep a bounded prefix plus length/hash as
	// key evidence instead of attempting to process pathological bytes.
	if len(raw) > MaxInputBytes {
		res.Verdict = VerdictUndetermined
		res.Rationale = fmt.Sprintf("无法判断：输入 %d 字节超过上限 %d，按超大输入隔离处理",
			len(raw), MaxInputBytes)
		res.Steps = []Step{{Name: "guard",
			Detail: fmt.Sprintf("raw input is %d bytes, limit %d", len(raw), MaxInputBytes)}}
		prefix := raw
		if len(prefix) > 256 {
			prefix = prefix[:256]
		}
		res.Evidence["raw_prefix_256"] = prefix
		res.Evidence["raw_len"] = fmt.Sprintf("%d", len(raw))
		res.Evidence["sha256"] = Digest(raw)
		return res
	}

	res.Steps = append(res.Steps, Step{Name: "ingest",
		Detail: fmt.Sprintf("accepted %d raw bytes, sha256=%s", len(raw), Digest(raw))})

	anchors, anchorFindings := splitAnchors(raw)
	res.Anchors = anchors
	res.Findings = append(res.Findings, anchorFindings...)
	res.Steps = append(res.Steps, Step{Name: "anchor",
		Detail: fmt.Sprintf("located %d/3 anchor markers: %s", len(anchors), markerList(anchors))})

	c, parseFinding, ok := parseCase(anchors)
	if !ok {
		res.Findings = append(res.Findings, parseFinding)
		res.Verdict = VerdictUndetermined
		res.Rationale = "无法判断：三段锚点不完整，无法构造校验用例"
		res.Evidence["raw_input"] = raw
		res.Steps = append(res.Steps, Step{Name: "parse", Detail: parseFinding.Message})
		return finish(res)
	}
	res.Steps = append(res.Steps, Step{Name: "parse",
		Detail: fmt.Sprintf("dns_name=%q labels=%d rule=%s",
			c.DNSName, len(c.EncodedLabels), c.ComparisonRule)})

	// The three anchors are also the three validation stages. Failures are
	// collected per anchor so the trigger position is unambiguous.
	res.Findings = append(res.Findings, validateName(raw, anchors, c.DNSName)...)
	res.Findings = append(res.Findings, validateEncoded(raw, anchors, c)...)
	res.Findings = append(res.Findings, validateRule(raw, anchors, c)...)

	res.Steps = append(res.Steps, Step{Name: "validate",
		Detail: fmt.Sprintf("%d finding(s) across ANCHOR1/2/3", len(res.Findings))})

	if len(res.Findings) > 0 {
		first := res.Findings[0]
		res.Verdict = VerdictDeny
		res.Rationale = fmt.Sprintf("拒绝：在锚点 %s（标记偏移 %d，字节原始偏移 %d，阶段 %s）触发 %s —— %s",
			first.Anchor, first.Offset, first.ByteOffset, first.Stage, first.Code, first.Message)
		res.Evidence["trigger_anchor"] = first.Anchor
		res.Evidence["trigger_offset"] = fmt.Sprintf("%d", first.Offset)
		res.Evidence["trigger_byte_offset"] = fmt.Sprintf("%d", first.ByteOffset)
	} else {
		res.Verdict = VerdictAllow
		res.Rationale = "放行：三段锚点全部通过 DNS 名称编码校验与比较规则"
	}
	res.Evidence["raw_input"] = raw
	res.Evidence["sha256"] = Digest(raw)
	return finish(res)
}

func finish(res Result) Result {
	res.Steps = append(res.Steps, Step{
		Name:   "conclude",
		Detail: fmt.Sprintf("verdict=%s findings=%d", res.Verdict, len(res.Findings)),
	})
	return res
}

func markerList(anchors []Anchor) string {
	parts := make([]string, 0, len(anchors))
	for _, a := range anchors {
		parts = append(parts, fmt.Sprintf("%s@%d", a.Marker, a.Offset))
	}
	return strings.Join(parts, ",")
}

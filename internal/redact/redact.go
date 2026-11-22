package redact

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"serrfix/internal/model"
)

type rule struct {
	name        string
	kind        string
	re          *regexp.Regexp
	startGroup  int
	endGroup    int
	replacement string
}

type candidate struct {
	start       int
	end         int
	rule        string
	kind        string
	replacement string
	priority    int
}

type Result struct {
	Original       []byte
	Redacted       []byte
	Spans          []model.Span
	Remaining      []model.Span
	TruncatedBytes int
}

var rules = []rule{
	{
		name: "pem_private_key", kind: "PRIVATE_KEY",
		re:         regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		startGroup: 0, endGroup: 0, replacement: "[REDACTED:PRIVATE_KEY]",
	},
	{
		name: "uri_userinfo", kind: "URI_USERINFO",
		re:         regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@`),
		startGroup: 2, endGroup: 3, replacement: "[REDACTED:URI_USERINFO]",
	},
	{
		name: "authorization_header", kind: "AUTHORIZATION",
		re:         regexp.MustCompile(`(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s,;"'\]\}]+)`),
		startGroup: 2, endGroup: 2, replacement: "[REDACTED:AUTHORIZATION]",
	},
	{
		name: "json_secret", kind: "JSON_SECRET",
		re:         regexp.MustCompile(`(?i)"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)"\s*:\s*"([^"]+)"`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:JSON_SECRET]",
	},
	{
		name: "key_value_secret", kind: "KEY_VALUE_SECRET",
		re:         regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*([^\s,;&}\]"']+)`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:KEY_VALUE_SECRET]",
	},
	{
		name: "bearer_token", kind: "BEARER_TOKEN",
		re:         regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{6,})`),
		startGroup: 2, endGroup: 2, replacement: "[REDACTED:BEARER_TOKEN]",
	},
	{
		name: "aws_access_key", kind: "AWS_ACCESS_KEY",
		re:         regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:AWS_ACCESS_KEY]",
	},
	{
		name: "github_token", kind: "GITHUB_TOKEN",
		re:         regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{20,})\b`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:GITHUB_TOKEN]",
	},
	{
		name: "jwt", kind: "JWT",
		re:         regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:JWT]",
	},
	{
		name: "email", kind: "EMAIL",
		re:         regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`),
		startGroup: 1, endGroup: 1, replacement: "[REDACTED:EMAIL]",
	},
}

func Redact(input []byte) Result {
	candidates := collectCandidates(input)
	selected := selectNonOverlapping(candidates)

	var out bytes.Buffer
	out.Grow(len(input) + len(selected)*8)
	spans := make([]model.Span, 0, len(selected))
	last := 0
	for i, c := range selected {
		if c.start < last || c.end > len(input) || c.start >= c.end {
			continue
		}
		out.Write(input[last:c.start])
		replacementOffset := out.Len()
		out.WriteString(c.replacement)
		line, column := lineColumn(input, c.start)
		spans = append(spans, model.Span{
			Ordinal:           i + 1,
			SourceOffset:      c.start,
			SourceLength:      c.end - c.start,
			Line:              line,
			Column:            column,
			Rule:              c.rule,
			Kind:              c.kind,
			Replacement:       c.replacement,
			ReplacementOffset: replacementOffset,
			OriginalSHA256:    model.SHA256(input[c.start:c.end]),
		})
		last = c.end
	}
	out.Write(input[last:])
	redacted := out.Bytes()

	return Result{
		Original:  append([]byte(nil), input...),
		Redacted:  redacted,
		Spans:     spans,
		Remaining: detect(redacted),
	}
}

func collectCandidates(input []byte) []candidate {
	var all []candidate
	for priority, r := range rules {
		matches := r.re.FindAllSubmatchIndex(input, -1)
		for _, m := range matches {
			startIdx, endIdx := r.startGroup*2, r.endGroup*2+1
			if endIdx >= len(m) || m[startIdx] < 0 || m[endIdx] < 0 {
				continue
			}
			start, end := m[startIdx], m[endIdx]
			if start >= end {
				continue
			}
			if bytes.HasPrefix(input[start:end], []byte("[REDACTED:")) {
				continue
			}
			all = append(all, candidate{
				start: start, end: end, rule: r.name, kind: r.kind,
				replacement: r.replacement, priority: priority,
			})
		}
	}
	return all
}

func selectNonOverlapping(in []candidate) []candidate {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		if in[i].priority != in[j].priority {
			return in[i].priority < in[j].priority
		}
		return in[i].end > in[j].end
	})
	out := make([]candidate, 0, len(in))
	lastEnd := -1
	for _, c := range in {
		if c.start < lastEnd {
			continue
		}
		out = append(out, c)
		lastEnd = c.end
	}
	return out
}

func detect(input []byte) []model.Span {
	candidates := selectNonOverlapping(collectCandidates(input))
	spans := make([]model.Span, 0, len(candidates))
	for i, c := range candidates {
		line, column := lineColumn(input, c.start)
		spans = append(spans, model.Span{
			Ordinal: i + 1, SourceOffset: c.start, SourceLength: c.end - c.start,
			Line: line, Column: column, Rule: c.rule, Kind: c.kind,
			OriginalSHA256: model.SHA256(input[c.start:c.end]),
		})
	}
	return spans
}

func lineColumn(data []byte, offset int) (int, int) {
	if offset > len(data) {
		offset = len(data)
	}
	line, column := 1, 1
	for _, b := range data[:offset] {
		if b == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return line, column
}

func Preview(data []byte, max int) string {
	if max <= 0 || len(data) <= max {
		return string(data)
	}
	return string(data[:max]) + fmt.Sprintf("...<%d bytes omitted>", len(data)-max)
}

func Mask(data []byte) string {
	s := string(data)
	if len(s) <= 120 {
		return s
	}
	return s[:56] + "..." + s[len(s)-48:]
}

func Summary(spans []model.Span) string {
	if len(spans) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(spans))
	for _, span := range spans {
		parts = append(parts, fmt.Sprintf("%s@%d+%d", span.Kind, span.SourceOffset, span.SourceLength))
	}
	return strings.Join(parts, ",")
}

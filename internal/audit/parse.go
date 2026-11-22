package audit

import (
	"bytes"
	"fmt"
	"strings"
)

type RangeResult struct {
	Records    []MountRecord
	Findings   []Finding
	Issues     []ParseIssue
	StopOffset int64
	Truncated  bool
}

type token struct {
	Value string
	Start int64
	End   int64
}

func ParseRange(data []byte, start, end int64, stage, baseOrdinal, maxRecords int) RangeResult {
	result := RangeResult{StopOffset: start}
	if start < 0 {
		start = 0
	}
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	if start >= end {
		return result
	}

	position := start
	lineNo := lineAt(data, start)
	for position < end {
		if len(result.Records) >= maxRecords {
			result.Truncated = true
			result.StopOffset = position
			return result
		}
		lineEnd := end
		next := end
		if index := bytes.IndexByte(data[position:end], '\n'); index >= 0 {
			lineEnd = position + int64(index)
			next = lineEnd + 1
		}
		rawEnd := lineEnd
		if rawEnd > position && data[rawEnd-1] == '\r' {
			rawEnd--
		}
		trimmed := bytes.TrimSpace(data[position:rawEnd])
		if len(trimmed) > 0 && trimmed[0] != '#' {
			record, issues := parseMountLine(data, position, rawEnd, lineNo, baseOrdinal+len(result.Records)+1, stage)
			if record != nil {
				result.Records = append(result.Records, *record)
				result.Findings = append(result.Findings, classifyMount(*record)...)
			}
			result.Issues = append(result.Issues, issues...)
		}
		position = next
		lineNo++
	}
	result.StopOffset = position
	return result
}

func parseMountLine(data []byte, start, end int64, lineNo, ordinal, stage int) (*MountRecord, []ParseIssue) {
	tokens := splitFields(data, start, end)
	if len(tokens) < 10 {
		return nil, []ParseIssue{{
			Stage:       stage,
			Code:        "invalid_field_count",
			Detail:      fmt.Sprintf("mountinfo line has %d fields, need at least 10", len(tokens)),
			StartOffset: start,
			EndOffset:   end,
			Line:        lineNo,
		}}
	}
	separator := -1
	for index := 6; index < len(tokens); index++ {
		if tokens[index].Value == "-" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+3 >= len(tokens) {
		return nil, []ParseIssue{{
			Stage:       stage,
			Code:        "missing_separator",
			Detail:      "mountinfo line lacks the '-' separator or trailing filesystem fields",
			StartOffset: start,
			EndOffset:   end,
			Line:        lineNo,
		}}
	}
	optionalValues := make([]string, 0, separator-6)
	for _, optional := range tokens[6:separator] {
		optionalValues = append(optionalValues, unescapeMount(optional.Value))
	}
	mountOptions := tokens[5].Value
	superOptions := tokens[separator+3].Value
	record := &MountRecord{
		Ordinal:      ordinal,
		Stage:        stage,
		MountID:      tokens[0].Value,
		ParentID:     tokens[1].Value,
		MajorMinor:   tokens[2].Value,
		Root:         unescapeMount(tokens[3].Value),
		MountPoint:   unescapeMount(tokens[4].Value),
		MountOptions: mountOptions,
		Optional:     strings.Join(optionalValues, " "),
		FSType:       unescapeMount(tokens[separator+1].Value),
		Source:       unescapeMount(tokens[separator+2].Value),
		SuperOptions: superOptions,
		Permissions:  parsePermissions(mountOptions, superOptions),
		StartOffset:  start,
		EndOffset:    end,
		Line:         lineNo,
	}
	return record, nil
}

func splitFields(data []byte, start, end int64) []token {
	tokens := make([]token, 0, 16)
	position := start
	for position < end {
		for position < end && isSpace(data[position]) {
			position++
		}
		if position >= end {
			break
		}
		tokenStart := position
		for position < end && !isSpace(data[position]) {
			position++
		}
		tokens = append(tokens, token{
			Value: string(data[tokenStart:position]),
			Start: tokenStart,
			End:   position,
		})
	}
	return tokens
}

func isSpace(value byte) bool {
	return value == ' ' || value == '\t'
}

func parsePermissions(mountOptions, superOptions string) Permissions {
	flags := optionSet(mountOptions)
	for flag := range optionSet(superOptions) {
		flags[flag] = true
	}
	return Permissions{
		ReadOnly: flags["ro"],
		NoSUID:   flags["nosuid"],
		NoDev:    flags["nodev"],
		NoExec:   flags["noexec"],
	}
}

func optionSet(options string) map[string]bool {
	set := make(map[string]bool)
	for _, option := range strings.Split(options, ",") {
		if option != "" {
			set[option] = true
		}
	}
	return set
}

func unescapeMount(value string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}

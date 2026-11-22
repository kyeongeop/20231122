package replay

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"seedreview/internal/model"
)

func ParseTrace(data []byte) (model.Trace, error) {
	var trace model.Trace
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &event); err != nil {
			return trace, fmt.Errorf("trace line %d is not JSON: %w", lineNumber, err)
		}
		switch event.Event {
		case "start":
			var item model.TraceStart
			if err := json.Unmarshal(line, &item); err != nil {
				return trace, fmt.Errorf("decode trace start line %d: %w", lineNumber, err)
			}
			trace.Starts = append(trace.Starts, item)
		case "permission":
			var item model.TracePermission
			if err := json.Unmarshal(line, &item); err != nil {
				return trace, fmt.Errorf("decode trace permission line %d: %w", lineNumber, err)
			}
			trace.Permissions = append(trace.Permissions, item)
		case "trigger":
			var item model.TraceTrigger
			if err := json.Unmarshal(line, &item); err != nil {
				return trace, fmt.Errorf("decode trace trigger line %d: %w", lineNumber, err)
			}
			trace.Triggers = append(trace.Triggers, item)
		case "log":
			var item model.TraceLog
			if err := json.Unmarshal(line, &item); err != nil {
				return trace, fmt.Errorf("decode trace log line %d: %w", lineNumber, err)
			}
			trace.Logs = append(trace.Logs, item)
		}
	}
	if err := scanner.Err(); err != nil {
		return trace, fmt.Errorf("read trace: %w", err)
	}
	return trace, nil
}

func traceExtensions(trace model.Trace) []model.ExtensionRecord {
	seen := make(map[string]int)
	var result []model.ExtensionRecord
	for _, start := range trace.Starts {
		index, exists := seen[start.Extension]
		if !exists {
			seen[start.Extension] = len(result)
			result = append(result, model.ExtensionRecord{
				Name: start.Extension, Known: start.KnownExtension,
				Source: "replay-trace",
				Details: map[string]any{
					"restored_seed":  start.RestoredSeed,
					"input_seed":     start.InputSeed,
					"effective_seed": start.EffectiveSeed,
					"principal":      start.Principal,
					"action":         start.Action,
				},
			})
			index = len(result) - 1
		}
		for position := range trace.Permissions {
			if trace.Permissions[position].Extension == start.Extension {
				permission := trace.Permissions[position]
				result[index].Permission = &permission
			}
		}
		for position := range trace.Triggers {
			if trace.Triggers[position].Extension == start.Extension {
				trigger := trace.Triggers[position]
				result[index].Trigger = &trigger
			}
		}
	}
	return result
}

func traceEffectiveSeed(trace model.Trace, fallback string) string {
	if len(trace.Starts) > 0 && trace.Starts[0].EffectiveSeed != "" {
		return trace.Starts[0].EffectiveSeed
	}
	return fallback
}

func ExtractLogs(stderr []byte, evidenceSHA string) []model.LogEvidence {
	var result []model.LogEvidence
	offset := 0
	sequence := 0
	for offset < len(stderr) {
		end := bytes.IndexByte(stderr[offset:], '\n')
		if end < 0 {
			end = len(stderr)
		} else {
			end += offset + 1
		}
		line := stderr[offset:end]
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[seed-audit]") {
			sequence++
			sum := sha256.Sum256(line)
			result = append(result, model.LogEvidence{
				Source: "seed_target", Sequence: sequence,
				Level: logLevel(trimmed), Message: trimmed,
				StartOffset: int64(offset), EndOffset: int64(end),
				LineSHA256:     hex.EncodeToString(sum[:]),
				EvidenceSHA256: evidenceSHA,
			})
		}
		offset = end
		if end == len(stderr) {
			break
		}
	}
	return result
}

func logLevel(line string) string {
	for _, level := range []string{"error", "warn", "info", "debug"} {
		if strings.Contains(line, "level="+level) {
			return level
		}
	}
	return "unknown"
}

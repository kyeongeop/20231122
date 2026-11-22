// Package ingest parses both wire formats of the dependency risk list.
//
// Legacy (v1): newline-delimited flat JSON objects, no envelope or checksum.
// New    (v2): length-prefixed frames "<len>\n<envelope-json>\n" where each
//
//	envelope carries a sha256 checksum of its payload.
//
// A truncated final frame/line is surfaced explicitly instead of being silently
// dropped, so the pipeline can recover and replay it with evidence intact.
package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"riskflow/internal/model"
)

// ErrTruncated marks an input whose final record is cut off mid-frame.
var ErrTruncated = errors.New("truncated record detected")

// Outcome is the parsed batch.
type Outcome struct {
	Schema    string
	BatchID   string
	Records   []model.Record
	Truncated bool
	Detail    string // human-readable truncation/checksum detail
}

// Parse auto-detects the format and returns normalized records.
func Parse(batchID string, raw []byte) (Outcome, error) {
	schema := Detect(raw)
	if schema == model.SchemaV2 {
		return parseV2(batchID, raw)
	}
	return parseV1(batchID, raw)
}

// Detect classifies the wire format using structural evidence only.
func Detect(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return model.SchemaV1
	}
	// v2 starts with an ASCII decimal length followed by '\n'.
	if idx := bytes.IndexByte(raw, '\n'); idx > 0 {
		if _, err := strconv.Atoi(string(raw[:idx])); err == nil {
			return model.SchemaV2
		}
	}
	// Otherwise treat the first non-space token as JSON (legacy JSONL/array).
	return model.SchemaV1
}

// ---- legacy v1 -------------------------------------------------------------

func parseV1(batchID string, raw []byte) (Outcome, error) {
	out := Outcome{Schema: model.SchemaV1, BatchID: batchID}
	lines := splitLines(raw)
	for i, line := range lines {
		payload := bytes.TrimSpace(line)
		if len(payload) == 0 {
			continue
		}
		if !json.Valid(payload) {
			// Last line with invalid/incomplete JSON is the truncated record.
			if i == len(lines)-1 {
				out.Truncated = true
				out.Detail = fmt.Sprintf("line %d is incomplete JSON (%d bytes)", i+1, len(payload))
				return out, ErrTruncated
			}
			return out, fmt.Errorf("line %d: malformed JSON", i+1)
		}
		rec, err := decodeFlat(payload)
		if err != nil {
			return out, fmt.Errorf("line %d: %w", i+1, err)
		}
		rec.Schema = model.SchemaV1
		rec.InputHash = hashBytes(payload)
		rec.Raw = string(payload)
		out.Records = append(out.Records, rec)
	}
	return out, nil
}

func decodeFlat(b []byte) (model.Record, error) {
	var flat struct {
		RecordID  string `json:"record_id"`
		Package   string `json:"package"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		Severity  string `json:"severity"`
		Decision  string `json:"decision"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal(b, &flat); err != nil {
		return model.Record{}, err
	}
	if flat.RecordID == "" || flat.Package == "" {
		return model.Record{}, errors.New("record_id and package are required")
	}
	return model.Record{
		RecordID:  flat.RecordID,
		Package:   flat.Package,
		Version:   flat.Version,
		Ecosystem: flat.Ecosystem,
		Severity:  flat.Severity,
		Decision:  flat.Decision,
		Role:      flat.Role,
	}, nil
}

// ---- new v2 ----------------------------------------------------------------

func parseV2(batchID string, raw []byte) (Outcome, error) {
	out := Outcome{Schema: model.SchemaV2, BatchID: batchID}
	pos := 0
	frame := 0
	for pos < len(raw) {
		frame++
		nl := bytes.IndexByte(raw[pos:], '\n')
		if nl < 0 {
			out.Truncated = true
			out.Detail = fmt.Sprintf("frame %d: missing length terminator", frame)
			return out, ErrTruncated
		}
		declared, err := strconv.Atoi(string(raw[pos : pos+nl]))
		if err != nil {
			return out, fmt.Errorf("frame %d: bad length prefix: %w", frame, err)
		}
		bodyStart := pos + nl + 1
		bodyEnd := bodyStart + declared
		if bodyEnd > len(raw) {
			// Declared frame runs past EOF: this is the truncated record.
			out.Truncated = true
			have := len(raw) - bodyStart
			out.Detail = fmt.Sprintf("frame %d: declared %d bytes but only %d present",
				frame, declared, have)
			return out, ErrTruncated
		}
		body := raw[bodyStart:bodyEnd]
		var env model.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			return out, fmt.Errorf("frame %d: envelope json: %w", frame, err)
		}
		if env.Schema != "" && env.Schema != model.SchemaV2 {
			return out, fmt.Errorf("frame %d: unexpected schema %q", frame, env.Schema)
		}
		if err := verifyChecksum(env, body); err != nil {
			return out, fmt.Errorf("frame %d: %w", frame, err)
		}
		rec := env.Payload
		rec.Schema = model.SchemaV2
		rec.Checksum = env.Checksum
		rec.InputHash = hashBytes(body)
		rec.Raw = string(body)
		if out.BatchID == "" && env.BatchID != "" {
			out.BatchID = env.BatchID
		}
		out.Records = append(out.Records, rec)
		pos = bodyEnd
		// Skip the single separating newline after the frame, if present.
		if pos < len(raw) && raw[pos] == '\n' {
			pos++
		}
	}
	return out, nil
}

func verifyChecksum(env model.Envelope, frameBody []byte) error {
	if env.Checksum == "" {
		return errors.New("missing checksum")
	}
	// Checksum is computed over the canonical payload JSON, independent of the
	// enclosing frame, so a re-serialized payload still verifies.
	payloadJSON, err := json.Marshal(env.Payload)
	if err != nil {
		return err
	}
	want := hashBytes(payloadJSON)
	if !strings.EqualFold(want, env.Checksum) {
		return fmt.Errorf("checksum mismatch: want %s got %s", want, env.Checksum)
	}
	return nil
}

// ---- helpers ---------------------------------------------------------------

func splitLines(raw []byte) [][]byte {
	// Preserve a trailing partial line: bytes.Split drops a final empty token
	// semantics, so split manually and keep the last fragment if non-empty.
	var lines [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			lines = append(lines, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

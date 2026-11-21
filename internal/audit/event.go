package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"auditfix/internal/model"
)

const hashDomain = "AFX-AUDIT-1"

type sourceEvent struct {
	Seq           int64  `json:"seq"`
	Device        string `json:"device"`
	TimeUnixNS    int64  `json:"time_unix_ns"`
	Kind          string `json:"kind"`
	AnchorID      string `json:"anchor_id"`
	Subject       string `json:"subject"`
	PayloadSHA256 string `json:"payload_sha256"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

func ParseDeviceLog(r io.Reader, expectedDevice string) ([]model.Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var events []model.Event
	lineNo := 0
	var previous *model.Event
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var src sourceEvent
		decoder := json.NewDecoder(bytes.NewBufferString(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&src); err != nil {
			return nil, fmt.Errorf("%s line %d: invalid JSON: %w", expectedDevice, lineNo, err)
		}
		if err := ensureJSONEnd(decoder); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", expectedDevice, lineNo, err)
		}
		if src.Device != expectedDevice {
			return nil, fmt.Errorf("%s line %d: device is %q, expected %q",
				expectedDevice, lineNo, src.Device, expectedDevice)
		}
		if err := validateSourceEvent(src); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", expectedDevice, lineNo, err)
		}
		computed := EventHash(src)
		hashValid := computed == strings.ToLower(src.RecordHash)
		relation := "genesis"
		if previous != nil {
			switch {
			case src.Seq == previous.Seq+1:
				if strings.EqualFold(src.PrevHash, previous.RecordHash) {
					relation = "contiguous"
				} else {
					relation = "broken_prev_hash"
				}
			case src.Seq > previous.Seq+1:
				if strings.EqualFold(src.PrevHash, previous.RecordHash) {
					relation = "gap_sealed"
				} else {
					relation = "gap_unresolved"
				}
			default:
				return nil, fmt.Errorf("%s line %d: sequence %d does not follow %d",
					expectedDevice, lineNo, src.Seq, previous.Seq)
			}
		}
		event := model.Event{
			Device:        src.Device,
			Ordinal:       len(events) + 1,
			Seq:           src.Seq,
			TimeUnixNS:    src.TimeUnixNS,
			CorrectedNS:   src.TimeUnixNS,
			Kind:          src.Kind,
			AnchorID:      src.AnchorID,
			Subject:       src.Subject,
			PayloadSHA256: strings.ToLower(src.PayloadSHA256),
			PrevHash:      strings.ToLower(src.PrevHash),
			RecordHash:    strings.ToLower(src.RecordHash),
			LineNo:        lineNo,
			RawLine:       raw,
			HashValid:     hashValid,
			ChainRelation: relation,
		}
		events = append(events, event)
		previous = &events[len(events)-1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: read log: %w", expectedDevice, err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%s: log contains no events", expectedDevice)
	}
	return events, nil
}

func EventHash(e sourceEvent) string {
	return HashEvent(e.Device, e.Seq, e.TimeUnixNS, e.Kind, e.AnchorID,
		e.Subject, e.PayloadSHA256, e.PrevHash)
}

func HashEvent(device string, seq, timeUnixNS int64, kind, anchorID,
	subject, payloadSHA256, prevHash string) string {
	var b strings.Builder
	b.WriteString(hashDomain)
	b.WriteByte('\n')
	b.WriteString(device)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(seq, 10))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(timeUnixNS, 10))
	b.WriteByte('\n')
	b.WriteString(kind)
	b.WriteByte('\n')
	b.WriteString(anchorID)
	b.WriteByte('\n')
	b.WriteString(subject)
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(payloadSHA256))
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(prevHash))
	b.WriteByte('\n')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func validateSourceEvent(e sourceEvent) error {
	if e.Seq < 1 {
		return errors.New("seq must be positive")
	}
	if e.TimeUnixNS <= 0 {
		return errors.New("time_unix_ns must be positive")
	}
	if e.Kind != "anchor" && e.Kind != "operation" && e.Kind != "heartbeat" {
		return fmt.Errorf("unsupported kind %q", e.Kind)
	}
	if e.Kind == "anchor" && strings.TrimSpace(e.AnchorID) == "" {
		return errors.New("anchor event requires anchor_id")
	}
	if strings.TrimSpace(e.Subject) == "" {
		return errors.New("subject is required")
	}
	for name, value := range map[string]string{
		"payload_sha256": e.PayloadSHA256,
		"prev_hash":      e.PrevHash,
		"record_hash":    e.RecordHash,
	} {
		if len(value) != 64 {
			return fmt.Errorf("%s must be 64 hex characters", name)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("%s is not hex: %w", name, err)
		}
	}
	return nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values on one line")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

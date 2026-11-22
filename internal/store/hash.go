package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"example.com/replay-review/internal/model"
)

// canonicalEvent renders an event with a fixed field order for hashing. The
// compact, key-sorted form is independent of the source file's formatting.
func canonicalEvent(ev model.Event) ([]byte, error) {
	return json.Marshal(canonicalJSON{
		Keys: []string{
			"sequence", "device_id", "code", "user_id",
			"kind", "observed_at", "offset_ms",
		},
		Vals: []any{
			ev.Sequence, ev.DeviceID, ev.Code, ev.UserID,
			ev.Kind, ev.ObservedAt, ev.OffsetMs,
		},
	})
}

// EventHash returns the lowercase hex SHA-256 of the canonical event JSON.
func EventHash(ev model.Event) (string, error) {
	raw, err := canonicalEvent(ev)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// EventHashes hashes a whole stream in order.
func EventHashes(events []model.Event) ([]string, error) {
	out := make([]string, len(events))
	for i, ev := range events {
		h, err := EventHash(ev)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// canonicalJSON marshals an ordered set of key/value pairs. Go's encoding/json
// preserves struct field order, so an anonymous struct gives stable output.
type canonicalJSON struct {
	Keys []string `json:"-"`
	Vals []any    `json:"-"`
}

// MarshalJSON emits keys in the exact order declared by Keys.
func (c canonicalJSON) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, 128)
	buf = append(buf, '{')
	for i, key := range c.Keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyRaw, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valRaw, err := json.Marshal(c.Vals[i])
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyRaw...)
		buf = append(buf, ':')
		buf = append(buf, valRaw...)
	}
	buf = append(buf, '}')
	return buf, nil
}

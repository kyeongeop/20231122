package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Token grammar snapshots recorded by this audit:
//
//	v1: PRT1:<8 hex id>:<unix expiry>
//	v2: PRT2:<base64url("id|expiry")>:<8 hex crc32 of payload>
//
// Anything else carrying the PRT prefix is treated as an unknown extension.
const (
	SnapshotV1 = "v1"
	SnapshotV2 = "v2"
)

type Token struct {
	Snapshot string // "v1" or "v2"
	ID       string
	Expiry   int64 // unix seconds
}

var ErrUnknownExtension = errors.New("unknown token extension")

func ParseToken(raw string) (*Token, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "PRT") {
		return nil, fmt.Errorf("malformed token: want 3 segments with PRT prefix")
	}
	switch parts[0] {
	case "PRT1":
		return parseV1(parts[1], parts[2])
	case "PRT2":
		return parseV2(parts[1], parts[2])
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownExtension, parts[0])
	}
}

func parseV1(id, expiryStr string) (*Token, error) {
	if len(id) != 8 || !isHex(id) {
		return nil, fmt.Errorf("v1: id must be 8 hex chars")
	}
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("v1: bad expiry: %v", err)
	}
	return &Token{Snapshot: SnapshotV1, ID: id, Expiry: expiry}, nil
}

func parseV2(payloadB64, crcHex string) (*Token, error) {
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("v2: payload not base64url: %v", err)
	}
	if crc32Hex(payload) != strings.ToLower(crcHex) {
		return nil, fmt.Errorf("v2: crc mismatch")
	}
	kv := strings.Split(string(payload), "|")
	if len(kv) != 2 {
		return nil, fmt.Errorf("v2: payload must be id|expiry")
	}
	expiry, err := strconv.ParseInt(kv[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("v2: bad expiry: %v", err)
	}
	return &Token{Snapshot: SnapshotV2, ID: kv[0], Expiry: expiry}, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

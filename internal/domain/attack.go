package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	SampleMagic   = "ASK1"
	SampleVersion = byte(1)
	SampleSize    = 24
	AttackV1      = "v1"
	AttackV2      = "v2"
)

var ErrInvalidSample = errors.New("invalid attack sample")

type ActorRole byte

const (
	RoleOwner ActorRole = iota
	RoleEditor
	RoleViewer
	RoleOutsider
)

func (r ActorRole) String() string {
	switch r {
	case RoleOwner:
		return "owner"
	case RoleEditor:
		return "editor"
	case RoleViewer:
		return "viewer"
	default:
		return "outsider"
	}
}

type Action byte

const (
	ActionRead Action = iota
	ActionUpdate
	ActionDelete
)

func (a Action) String() string {
	switch a {
	case ActionRead:
		return "read"
	case ActionUpdate:
		return "update"
	case ActionDelete:
		return "delete"
	default:
		return "unknown"
	}
}

const (
	PermRead   byte = 1 << 0
	PermUpdate byte = 1 << 1
	PermDelete byte = 1 << 2
)

func (a Action) Permission() byte {
	switch a {
	case ActionRead:
		return PermRead
	case ActionUpdate:
		return PermUpdate
	default:
		return PermDelete
	}
}

type Attack struct {
	ActorRole     ActorRole `json:"actor_role"`
	Action        Action    `json:"action"`
	TenantMatch   bool      `json:"tenant_match"`
	RequestDevice string    `json:"request_device"`
	SkewAMS       int32     `json:"device_a_skew_ms"`
	SkewBMS       int32     `json:"device_b_skew_ms"`
}

func DecodeAttack(input []byte) (Attack, error) {
	if len(input) < SampleSize {
		return Attack{}, fmt.Errorf("%w: got %d bytes, need %d", ErrInvalidSample, len(input), SampleSize)
	}
	if string(input[0:4]) != SampleMagic {
		return Attack{}, fmt.Errorf("%w: bad magic %q", ErrInvalidSample, input[0:4])
	}
	if input[4] != SampleVersion {
		return Attack{}, fmt.Errorf("%w: unsupported version %d", ErrInvalidSample, input[4])
	}
	if input[5] > byte(RoleOutsider) {
		return Attack{}, fmt.Errorf("%w: actor role %d", ErrInvalidSample, input[5])
	}
	if input[6] > byte(ActionDelete) {
		return Attack{}, fmt.Errorf("%w: action %d", ErrInvalidSample, input[6])
	}
	device := "device-a"
	if input[7]&2 != 0 {
		device = "device-b"
	}
	return Attack{
		ActorRole:     ActorRole(input[5]),
		Action:        Action(input[6]),
		TenantMatch:   input[7]&1 != 0,
		RequestDevice: device,
		SkewAMS:       int32(binary.LittleEndian.Uint32(input[8:12])),
		SkewBMS:       int32(binary.LittleEndian.Uint32(input[12:16])),
	}, nil
}

func EncodeAttack(a Attack) ([]byte, error) {
	if a.ActorRole > RoleOutsider {
		return nil, fmt.Errorf("%w: actor role %d", ErrInvalidSample, a.ActorRole)
	}
	if a.Action > ActionDelete {
		return nil, fmt.Errorf("%w: action %d", ErrInvalidSample, a.Action)
	}
	flags := byte(0)
	if a.TenantMatch {
		flags |= 1
	}
	if a.RequestDevice == "device-b" {
		flags |= 2
	}
	out := make([]byte, SampleSize)
	copy(out[0:4], SampleMagic)
	out[4] = SampleVersion
	out[5] = byte(a.ActorRole)
	out[6] = byte(a.Action)
	out[7] = flags
	binary.LittleEndian.PutUint32(out[8:12], uint32(a.SkewAMS))
	binary.LittleEndian.PutUint32(out[12:16], uint32(a.SkewBMS))
	return out, nil
}

func MustEncodeAttack(a Attack) []byte {
	out, err := EncodeAttack(a)
	if err != nil {
		panic(err)
	}
	return out
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Hex(input []byte) string {
	return hex.EncodeToString(input)
}

package forensics

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrInvalidMagic     = errors.New("invalid RZ31 magic")
	ErrTruncated        = errors.New("truncated record")
	ErrUnknownExtension = errors.New("unregistered extension tag")
)

var registeredExtensions = map[uint8]string{
	0x01: "base-image",
	0x02: "delta",
	0x03: "zstd-frame",
	0x05: "index",
}

type UnknownExtension struct {
	Tag          uint8  `json:"tag"`
	TagOffset    int    `json:"tag_offset"`
	LengthOffset int    `json:"length_offset"`
	DataOffset   int    `json:"data_offset"`
	Length       uint32 `json:"length"`
	Boundary     int    `json:"boundary"`
	DataHex      string `json:"data_hex"`
}

type Analysis struct {
	Magic        string            `json:"magic"`
	Version      uint8             `json:"version"`
	DeclaredSize uint32            `json:"declared_size"`
	RecordCount  uint16            `json:"record_count"`
	RecordLength uint32            `json:"record_length"`
	PayloadStart int               `json:"payload_start"`
	PayloadLen   int               `json:"payload_len"`
	Extension    uint8             `json:"extension"`
	ExtensionLen uint32            `json:"extension_length"`
	Registry     map[uint8]string  `json:"registry"`
	Unknown      *UnknownExtension `json:"unknown_extension,omitempty"`
}

// AnalyzeSample follows the same record boundary checks as the libFuzzer
// harness. It stops before assigning meaning to an unregistered extension.
func AnalyzeSample(data []byte) (Analysis, error) {
	out := Analysis{
		Registry: registeredExtensions,
	}
	if len(data) < 29 {
		return out, ErrTruncated
	}
	if string(data[0:4]) != "RZ31" {
		return out, ErrInvalidMagic
	}

	out.Magic = "RZ31"
	out.Version = data[4]
	out.DeclaredSize = binary.BigEndian.Uint32(data[6:10])
	out.RecordCount = binary.BigEndian.Uint16(data[14:16])
	out.RecordLength = binary.BigEndian.Uint32(data[16:20])
	out.Extension = data[20]
	out.ExtensionLen = binary.BigEndian.Uint32(data[21:25])

	payloadStart := 29 + int(out.ExtensionLen)
	if payloadStart > len(data) {
		return out, ErrTruncated
	}
	out.PayloadStart = payloadStart
	out.PayloadLen = len(data) - payloadStart

	if name, ok := registeredExtensions[out.Extension]; !ok {
		out.Unknown = &UnknownExtension{
			Tag:          out.Extension,
			TagOffset:    UnknownTagOff,
			LengthOffset: UnknownLenOff,
			DataOffset:   UnknownDataOff,
			Length:       out.ExtensionLen,
			Boundary:     payloadStart,
			DataHex:      Hex(data[UnknownDataOff:payloadStart]),
		}
		return out, fmt.Errorf("%w: 0x%02x", ErrUnknownExtension, out.Extension)
	} else {
		_ = name
	}

	return out, nil
}

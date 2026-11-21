// Package material builds the canonical sealed blob used by the key-rotation
// exercise. The blob contains three anchored sections:
//
//	ANCHOR#1  header      - rotating key id + epoch
//	ANCHOR#2  payload     - encrypted frame + client key epoch
//	ANCHOR#3  attestation - replay-protection record (expected epoch)
package material

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Magic1/Magic2/Magic3 are the three anchor markers. Each is 8 bytes so
	// the recorded raw offsets stay unambiguous inside the sealed blob.
	Magic1 = "KRFIXH01"
	Magic2 = "KRFIXP02"
	Magic3 = "KRFIXA03"

	// AnchorCount is the number of anchors every accepted blob must expose.
	AnchorCount = 3

	headerLen      = 8 + 4 + 4 // magic + key_id + server_epoch
	payloadLen     = 8 + 4 + 4 + 32
	attestationLen = 8 + 4 + 32
)

// Anchor describes one located section inside the sealed blob. Offsets are
// raw byte offsets measured from byte zero of the original material.
type Anchor struct {
	Index  int    `json:"index"`
	Magic  string `json:"magic"`
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

// Frame is the structured view of one sealed blob.
type Frame struct {
	KeyID       uint32
	ServerEpoch uint32
	ClientEpoch uint32
	Cipher      [32]byte
	AttestEpoch uint32
	AttestTag   [32]byte
	Anchors     []Anchor
	TotalLen    int64
}

var magics = [AnchorCount]string{Magic1, Magic2, Magic3}
var names = [AnchorCount]string{"header", "payload", "attestation"}
var lens = [AnchorCount]int{headerLen, payloadLen, attestationLen}

// Locate scans raw material and returns the raw offsets of the three anchors.
// It never mutates the input.
func Locate(raw []byte) ([]Anchor, error) {
	anchors := make([]Anchor, 0, AnchorCount)
	next := int64(0)
	for i := 0; i < AnchorCount; i++ {
		idx := bytes.Index(raw[next:], []byte(magics[i]))
		if idx < 0 {
			return nil, fmt.Errorf("anchor #%d (%s) not found", i+1, magics[i])
		}
		off := next + int64(idx)
		if off+int64(lens[i]) > int64(len(raw)) {
			return nil, fmt.Errorf("anchor #%d truncated at offset %d", i+1, off)
		}
		anchors = append(anchors, Anchor{
			Index: i + 1, Magic: magics[i], Name: names[i],
			Offset: off, Length: int64(lens[i]),
		})
		next = off + int64(lens[i])
	}
	return anchors, nil
}

// Parse decodes the fields of a located frame.
func Parse(raw []byte, anchors []Anchor) (*Frame, error) {
	if len(anchors) != AnchorCount {
		return nil, errors.New("expected three anchors")
	}
	f := &Frame{Anchors: anchors, TotalLen: int64(len(raw))}
	readU32 := func(anchor, field int) uint32 {
		base := anchors[anchor].Offset + 8 + int64(field*4)
		return binary.BigEndian.Uint32(raw[base : base+4])
	}
	f.KeyID = readU32(0, 0)
	f.ServerEpoch = readU32(0, 1)
	f.ClientEpoch = readU32(1, 0)
	copy(f.Cipher[:], raw[anchors[1].Offset+16:anchors[1].Offset+16+32])
	f.AttestEpoch = readU32(2, 0)
	copy(f.AttestTag[:], raw[anchors[2].Offset+12:anchors[2].Offset+12+32])
	return f, nil
}

// Build assembles a sealed frame from the supplied fields. The output is
// deterministic so generated original material can be hash-pinned.
func Build(keyID, serverEpoch, clientEpoch, attestEpoch uint32,
	cipher, attestTag [32]byte) []byte {
	var b bytes.Buffer
	put := func(magic string, fields ...uint32) {
		b.WriteString(magic)
		for _, v := range fields {
			var tmp [4]byte
			binary.BigEndian.PutUint32(tmp[:], v)
			b.Write(tmp[:])
		}
	}
	put(Magic1, keyID, serverEpoch)
	put(Magic2, clientEpoch, 0 /* reserved */)
	b.Write(cipher[:])
	put(Magic3, attestEpoch)
	b.Write(attestTag[:])
	return b.Bytes()
}

// SHA256 returns the hex digest of raw material.
func SHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum)
}

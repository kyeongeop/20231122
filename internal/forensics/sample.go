package forensics

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const (
	SampleName     = "recovered_0x7e.kz3"
	SampleCase     = "C-8842"
	Extension      = ".kz3"
	UnknownTag     = 0x7e
	UnknownTagOff  = 0x14
	UnknownDataOff = 0x1d
	UnknownLenOff  = 0x15
)

// BuildSeedSample returns the exact 84-byte input preserved in SQLite.
// The container deliberately uses an unregistered extension tag (0x7e).
func BuildSeedSample() []byte {
	b := make([]byte, 84)
	copy(b[0:4], "RZ31")
	b[4] = 0x02
	b[5] = 0x04
	binary.BigEndian.PutUint32(b[6:10], uint32(len(b)))
	binary.BigEndian.PutUint16(b[10:12], 0x0001)
	binary.BigEndian.PutUint16(b[12:14], 0x0000)
	binary.BigEndian.PutUint16(b[14:16], 0x0001)

	binary.BigEndian.PutUint32(b[16:20], uint32(len(b)-16))
	b[20] = UnknownTag
	binary.BigEndian.PutUint32(b[21:25], 12)
	binary.BigEndian.PutUint16(b[25:27], 0x0003)
	binary.BigEndian.PutUint16(b[27:29], 0x0000)
	copy(b[29:41], []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
		0x00, 0x01, 0x52, 0x5a, 0x00, 0x07,
	})

	payload := []byte{0x78, 0xda, 0x01, 0x00}
	payload = append(payload, []byte("kz3/record.c:88:trace")...)
	copy(b[41:], payload)
	return b
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Hex(data []byte) string {
	return hex.EncodeToString(data)
}

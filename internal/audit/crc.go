package audit

import (
	"fmt"
	"hash/crc32"
)

func crc32Hex(b []byte) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE(b))
}

// MintV2 builds a well-formed v2 token, used by seeds, tests and fuzz corpus.
func MintV2(id string, expiry int64) string {
	payload := fmt.Sprintf("%s|%d", id, expiry)
	b64 := base64RawURLEncode([]byte(payload))
	return "PRT2:" + b64 + ":" + crc32Hex([]byte(payload))
}

package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func JSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func JSONIndent(value any) ([]byte, error) {
	return json.MarshalIndent(value, "", "  ")
}

func Bytes(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func Sum(value any) string {
	sum := sha256.Sum256(Bytes(value))
	return hex.EncodeToString(sum[:])
}

func SumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

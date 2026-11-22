package taint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"taintlab/internal/model"
)

func ExecuteReader(reader io.Reader) (model.Result, error) {
	if reader == nil {
		return Execute(nil), nil
	}
	var (
		hasher   = sha256.New()
		stored   = make([]byte, 0, MaxInputBytes)
		preview  = make([]byte, 0, 256)
		size     int
		oversize bool
		chunk    = make([]byte, 32*1024)
	)
	for {
		count, err := reader.Read(chunk)
		if count > 0 {
			size += count
			if _, hashErr := hasher.Write(chunk[:count]); hashErr != nil {
				return model.Result{}, fmt.Errorf("hash input: %w", hashErr)
			}
			remainingPreview := 256 - len(preview)
			if remainingPreview > 0 {
				take := count
				if take > remainingPreview {
					take = remainingPreview
				}
				preview = append(preview, chunk[:take]...)
			}
			if !oversize && size <= MaxInputBytes {
				stored = append(stored, chunk[:count]...)
			} else {
				oversize = true
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.Result{}, fmt.Errorf("read input: %w", err)
		}
	}
	if oversize {
		return oversizedResult(size, hex.EncodeToString(hasher.Sum(nil)), preview), nil
	}
	return Execute(stored), nil
}

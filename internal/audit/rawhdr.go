package audit

import "errors"

// HeaderName extracts the entry name from a raw 512-byte tar header block.
// It never panics on malformed input, which makes it a safe fuzz target.
func HeaderName(block []byte) (string, error) {
	if len(block) < 512 {
		return "", errors.New("short header block")
	}
	end := 0
	for end < 100 && block[end] != 0 {
		end++
	}
	return string(block[:end]), nil
}

// HeaderMode extracts the mode field (octal ASCII at bytes 100..107).
func HeaderMode(block []byte) (uint32, error) {
	if len(block) < 512 {
		return 0, errors.New("short header block")
	}
	var mode uint32
	for _, c := range block[100:108] {
		if c == 0 || c == ' ' {
			continue
		}
		if c < '0' || c > '7' {
			return 0, errors.New("invalid octal digit in mode")
		}
		mode = mode<<3 | uint32(c-'0')
	}
	return mode, nil
}

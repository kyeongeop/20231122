// Package parse decodes LFI evidence objects from the legacy v1 flat format
// and the current v2 versioned-envelope format. Truncated objects are
// recovered on a best-effort basis so a cut-off record never aborts the run.
package parse

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"lfireview/internal/model"
)

// Snapshot versions understood by the parser.
const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

// Decode parses one evidence object serialized in the given snapshot format.
// source is the object name inside the snapshot, used for provenance.
//
// A truncated object yields a record with StatusTruncated and every field
// that could be recovered from the valid prefix, plus the original bytes.
// Garbage that cannot be interpreted as an object yields StatusMalformed.
// Decode never panics: malformed UTF-8 and partial tokens are handled here.
func Decode(version, source string, data []byte) (rec model.EvidenceRecord, err error) {
	rec = model.EvidenceRecord{
		SnapshotVersion: version,
		SourceObject:    source,
		Raw:             append([]byte(nil), data...),
	}

	defer func() {
		if r := recover(); r != nil {
			rec.Status = model.StatusMalformed
			rec.ParseError = "panic: " + panicText(r)
			err = nil
		}
	}()

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		rec.Status = model.StatusMalformed
		rec.ParseError = "empty object"
		return rec, nil
	}

	var strictErr error
	switch version {
	case VersionV1:
		var v1 v1Object
		strictErr = json.Unmarshal(trimmed, &v1)
		if strictErr == nil {
			rec = mergeV1(rec, v1)
			rec.Status = model.StatusOK
			return rec, nil
		}
		if isTruncation(strictErr) {
			if v1, ok := tolerantV1(trimmed); ok {
				rec = mergeV1(rec, v1)
				markTruncated(&rec, strictErr)
				return rec, nil
			}
		}
	case VersionV2:
		var v2 v2Envelope
		strictErr = json.Unmarshal(trimmed, &v2)
		if strictErr == nil {
			rec = mergeV2(rec, v2)
			rec.Status = model.StatusOK
			return rec, nil
		}
		if isTruncation(strictErr) {
			if v2, ok := tolerantV2(trimmed); ok {
				rec = mergeV2(rec, v2)
				markTruncated(&rec, strictErr)
				return rec, nil
			}
		}
	default:
		rec.Status = model.StatusMalformed
		rec.ParseError = "unknown snapshot version: " + version
		return rec, nil
	}

	rec.Status = model.StatusMalformed
	rec.ParseError = strictErr.Error()
	return rec, nil
}

func markTruncated(rec *model.EvidenceRecord, cause error) {
	rec.Status = model.StatusTruncated
	if cause != nil {
		rec.ParseError = cause.Error()
	} else {
		rec.ParseError = "object ends before the closing token"
	}
}

// isTruncation reports whether a JSON error indicates the input was cut off
// rather than syntactically wrong from the start.
func isTruncation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return contains(msg, "unexpected end of JSON input") ||
		contains(msg, "unexpected EOF")
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func panicText(r any) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	default:
		return "recovered"
	}
}

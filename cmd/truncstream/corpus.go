package main

import (
	"os"
	"path/filepath"

	"truncstream/internal/stream"
)

// cmdCorpus emits seed files for both Go fuzzing and the libFuzzer C
// harness. Seeds cover: valid compressed stream, truncated header,
// truncated payload, bad magic, corrupted payload and empty input.
func cmdCorpus(args []string) error {
	if len(args) != 1 {
		return os.ErrInvalid
	}
	dir := args[0]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	recs := stream.GenRecords(101, "obj-seed", 9, 1000, 50, 7)
	full, err := stream.BuildStream(recs, stream.EncodeOptions{Compress: true})
	if err != nil {
		return err
	}
	seeds := map[string][]byte{
		"valid_compressed":  full,
		"truncated_header":  full[:6],
		"truncated_payload": full[:len(full)-3],
		"bad_magic":         append([]byte("XXXX"), full[4:]...),
		"empty":             {},
		"tiny":              []byte{1, 2, 3},
		"no_eof":            mustBuild(recs, stream.EncodeOptions{Compress: true, OmitEOF: true}),
		"uncompressed":      mustBuild(recs, stream.EncodeOptions{Compress: false}),
	}
	corruptSeq := uint64(4)
	seeds["corrupt_payload"] = mustBuild(recs, stream.EncodeOptions{
		Compress: true, CorruptSeq: &corruptSeq,
	})
	for name, data := range seeds {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mustBuild(recs []stream.Record, opt stream.EncodeOptions) []byte {
	b, err := stream.BuildStream(recs, opt)
	if err != nil {
		panic(err)
	}
	return b
}

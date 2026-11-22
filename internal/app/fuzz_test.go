package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPackFuzzBundlePreservesPayloadOffsets(t *testing.T) {
	root := t.TempDir()
	firstDir := filepath.Join(root, "one")
	secondDir := filepath.Join(root, "two")
	for _, dir := range []string{firstDir, secondDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	firstPath := filepath.Join(firstDir, "hash-name")
	secondPath := filepath.Join(secondDir, "hash-name")
	first := []byte("password=first\n\x00\xff")
	second := []byte("Authorization: Bearer second")
	if err := os.WriteFile(firstPath, first, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, second, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle, records, err := packFuzzBundle([]string{firstPath, secondPath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bundle, []byte(fuzzBundleMagic)) {
		t.Fatalf("missing bundle magic")
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].Name == records[1].Name {
		t.Fatalf("duplicate corpus names were not disambiguated")
	}
	for i, want := range [][]byte{first, second} {
		record := records[i]
		got := bundle[record.BundleOffset : record.BundleOffset+record.Length]
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %d offset changed\n got: %q\nwant: %q", i, got, want)
		}
	}
}

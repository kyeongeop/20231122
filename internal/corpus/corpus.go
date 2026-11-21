// Package corpus snapshots a libFuzzer corpus into a deterministic sequence.
package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is the immutable corpus metadata stored with a run. Seq is one-based
// and is also the record order used by resume and export.
type Entry struct {
	Seq    int64
	Name   string
	SHA256 string
	Bytes  int64
}

func Scan(root string) ([]Entry, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, "", fmt.Errorf("stat corpus: %w", err)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("corpus %q is not a directory", root)
	}

	var entries []Entry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		sha, size, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", rel, err)
		}
		entries = append(entries, Entry{Name: rel, SHA256: sha, Bytes: size})
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("corpus %q contains no regular files", root)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	h := sha256.New()
	for i := range entries {
		entries[i].Seq = int64(i + 1)
		fmt.Fprintf(h, "%s\x00%s\x00%d\n", entries[i].Name, entries[i].SHA256, entries[i].Bytes)
	}
	return entries, hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Open returns the source file for an entry. The caller must close it.
func Open(root string, e Entry) (*os.File, error) {
	clean := filepath.FromSlash(e.Name)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("unsafe corpus path %q", e.Name)
	}
	return os.Open(filepath.Join(root, clean))
}

func Fingerprint(entries []Entry) string {
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%s\x00%d\n", e.Name, e.SHA256, e.Bytes)
	}
	return hex.EncodeToString(h.Sum(nil))
}

package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ManifestEntry struct {
	Path   string
	SHA256 string
	Bytes  int64
}

func WriteManifest(dir string) ([]ManifestEntry, error) {
	var entries []ManifestEntry
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name == "MANIFEST.sha256" || strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		entries = append(entries, ManifestEntry{
			Path:   filepath.ToSlash(rel),
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(data)),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	var b strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&b, "%s  %s\n", entry.SHA256, entry.Path)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.sha256"), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	return entries, nil
}

func VerifyManifest(dir string) (int, []string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "MANIFEST.sha256"))
	if err != nil {
		return 0, nil, err
	}
	lines := strings.Split(string(data), "\n")
	total := 0
	var errors []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			errors = append(errors, "malformed: "+line)
			continue
		}
		total++
		path := filepath.Join(dir, filepath.FromSlash(parts[1]))
		fileData, readErr := os.ReadFile(path)
		if readErr != nil {
			errors = append(errors, readErr.Error())
			continue
		}
		sum := sha256.Sum256(fileData)
		if hex.EncodeToString(sum[:]) != parts[0] {
			errors = append(errors, "sha256 mismatch: "+parts[1])
		}
	}
	return total, errors, nil
}

package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"auditfix/internal/db"
	"auditfix/internal/model"
)

func canonicalJSON(value any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(path string, value any) error {
	data, err := canonicalJSON(value, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeJSONL(path string, rows []any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, row := range rows {
		data, err := canonicalJSON(row, false)
		if err != nil {
			return err
		}
		buf.Write(data)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func sha256File(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func collectFiles(root, databasePath string) ([]FileEntry, error) {
	var files []FileEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestName || rel == DigestName || rel == databasePath {
			return nil
		}
		sum, size, err := sha256File(path)
		if err != nil {
			return err
		}
		files = append(files, FileEntry{Path: rel, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func snapshotDatabase(ctx context.Context, store *db.Store, target string) error {
	if _, err := store.SQL().ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint sqlite before export: %w", err)
	}
	escaped := filepath.ToSlash(target)
	escaped = "'" + bytesReplacer(escaped) + "'"
	if _, err := store.SQL().ExecContext(ctx, "VACUUM INTO "+escaped); err != nil {
		return fmt.Errorf("snapshot sqlite: %w", err)
	}
	return nil
}

func bytesReplacer(value string) string {
	return string(bytes.ReplaceAll([]byte(value), []byte("'"), []byte("''")))
}

func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func modelSampleToRow(sample model.Sample, path string) SampleRow {
	return SampleRow{
		SampleID: sample.SampleID, CaseID: sample.CaseID,
		SampleIndex: sample.SampleIndex, Name: sample.Name,
		SHA256: sample.SHA256, Size: sample.Size,
		SourceName: sample.SourceName, ImportedAt: sample.ImportedAt,
		BundlePath: path,
	}
}

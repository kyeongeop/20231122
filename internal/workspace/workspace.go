package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"serrfix/internal/model"
	"serrfix/internal/store"
)

type Workspace struct {
	Root string
}

func Open(root string) (Workspace, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Workspace{}, err
	}
	return Workspace{Root: abs}, nil
}

func (w Workspace) DBPath() string       { return filepath.Join(w.Root, "evidence.db") }
func (w Workspace) MaterialsDir() string { return filepath.Join(w.Root, "materials") }
func (w Workspace) RunsDir() string      { return filepath.Join(w.Root, "runs") }
func (w Workspace) FuzzDir() string      { return filepath.Join(w.Root, "fuzz") }
func (w Workspace) BinDir() string       { return filepath.Join(w.Root, "bin") }
func (w Workspace) ExportsDir() string   { return filepath.Join(w.Root, "exports") }
func (w Workspace) Resolve(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(w.Root, rel)
}

func (w Workspace) Rel(abs string) (string, error) {
	return filepath.Rel(w.Root, abs)
}

func (w Workspace) Ensure() error {
	for _, dir := range []string{
		w.Root, w.MaterialsDir(), w.RunsDir(), w.FuzzDir(), w.BinDir(), w.ExportsDir(),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (w Workspace) OpenDB() (*store.DB, error) {
	return store.Open(w.DBPath())
}

type Snapshot struct {
	Material store.Material
	Path     string
}

func (w Workspace) SnapshotMaterial(sourcePath, role string, capturedAt time.Time) (Snapshot, error) {
	src, err := os.Open(sourcePath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open original: %w", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("original is not a regular file: %s", sourcePath)
	}

	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return Snapshot{}, err
	}
	dir := filepath.Join(w.MaterialsDir(), role)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Snapshot{}, err
	}
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return Snapshot{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err != nil {
		tmp.Close()
		return Snapshot{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Snapshot{}, err
	}
	if err := tmp.Close(); err != nil {
		return Snapshot{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	finalName := fmt.Sprintf("%s-%s.bin", sanitize(filepath.Base(sourcePath)), sum[:12])
	finalPath := filepath.Join(dir, finalName)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return Snapshot{}, err
	}
	if err := os.Chmod(finalPath, 0o444); err != nil {
		return Snapshot{}, err
	}
	if err := os.Chtimes(finalPath, info.ModTime(), info.ModTime()); err != nil {
		return Snapshot{}, err
	}
	rel, err := w.Rel(finalPath)
	if err != nil {
		return Snapshot{}, err
	}
	material := store.Material{
		ID:            "mat-" + sum[:16],
		Role:          role,
		SourcePath:    absSource,
		SnapshotPath:  rel,
		SHA256:        sum,
		Size:          size,
		OriginalMTime: model.Timestamp(info.ModTime()),
		CapturedAt:    model.Timestamp(capturedAt),
		Immutable:     true,
	}
	return Snapshot{Material: material, Path: finalPath}, nil
}

func (w Workspace) SnapshotBytes(role, name, sourceLabel string, data []byte, capturedAt time.Time) (Snapshot, error) {
	sum := model.SHA256(data)
	dir := filepath.Join(w.MaterialsDir(), role)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Snapshot{}, err
	}
	finalPath := filepath.Join(dir, fmt.Sprintf("%s-%s.bin", sanitize(name), sum[:12]))
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return Snapshot{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Snapshot{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Snapshot{}, err
	}
	if err := tmp.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := os.Chmod(tmpPath, 0o444); err != nil {
		return Snapshot{}, err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return Snapshot{}, err
	}
	if err := os.Chtimes(finalPath, capturedAt, capturedAt); err != nil {
		return Snapshot{}, err
	}
	rel, err := w.Rel(finalPath)
	if err != nil {
		return Snapshot{}, err
	}
	material := store.Material{
		ID: "mat-" + sum[:16], Role: role, SourcePath: sourceLabel,
		SnapshotPath: rel, SHA256: sum, Size: int64(len(data)),
		OriginalMTime: model.Timestamp(capturedAt),
		CapturedAt:    model.Timestamp(capturedAt), Immutable: true,
	}
	return Snapshot{Material: material, Path: finalPath}, nil
}

func (w Workspace) ReadSlice(m store.Material, offset, length int64) ([]byte, error) {
	if offset < 0 || length <= 0 || offset+length > m.Size {
		return nil, fmt.Errorf("invalid slice offset=%d length=%d size=%d", offset, length, m.Size)
	}
	path := w.Resolve(m.SnapshotPath)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, offset); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if got := model.SHA256(buf); got != m.SHA256 && length == m.Size {
		return nil, fmt.Errorf("material hash mismatch: got %s want %s", got, m.SHA256)
	}
	return buf, nil
}

func CheckMaterial(root string, m store.Material) error {
	data, err := os.ReadFile(filepath.Join(root, m.SnapshotPath))
	if err != nil {
		return err
	}
	if int64(len(data)) != m.Size {
		return fmt.Errorf("size mismatch: got %d want %d", len(data), m.Size)
	}
	if got := model.SHA256(data); got != m.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, m.SHA256)
	}
	info, err := os.Stat(filepath.Join(root, m.SnapshotPath))
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("snapshot is writable: mode %o", info.Mode().Perm())
	}
	return nil
}

type Line struct {
	Offset int64
	Length int64
	Data   []byte
}

func SplitLines(data []byte) []Line {
	var lines []Line
	start := 0
	for i, b := range data {
		if b != '\n' {
			continue
		}
		if i > start {
			lines = append(lines, Line{
				Offset: int64(start),
				Length: int64(i - start),
				Data:   append([]byte(nil), data[start:i]...),
			})
		}
		start = i + 1
	}
	if start < len(data) {
		lines = append(lines, Line{
			Offset: int64(start),
			Length: int64(len(data) - start),
			Data:   append([]byte(nil), data[start:]...),
		})
	}
	return lines
}

func LabelFor(data []byte, ordinal int) string {
	text := string(data)
	if strings.HasPrefix(text, "[") {
		if end := strings.Index(text, "]"); end > 1 && end < 80 {
			return text[1:end]
		}
	}
	if colon := strings.IndexByte(text, ':'); colon > 0 && colon < 48 {
		return text[:colon]
	}
	return fmt.Sprintf("case-%03d", ordinal)
}

func BuildSample(line Line, material store.Material, ordinal int, createdAt time.Time, rerunCommand string) (model.Sample, error) {
	label := LabelFor(line.Data, ordinal)
	params := model.DefaultParams(label)
	sum := model.SHA256(line.Data)
	id := fmt.Sprintf("s-%03d-%s", ordinal, sum[:12])
	source := model.SourceRef{
		MaterialID: material.ID,
		Offset:     line.Offset,
		Length:     line.Length,
		SHA256:     sum,
	}
	c := model.Case{
		Schema: model.SchemaCase, SampleID: id, Label: label,
		Origin: "original-lines", Params: params, Source: source,
		CreatedAt: model.Timestamp(createdAt), Command: rerunCommand,
	}
	caseJSON, err := model.CanonicalJSON(c)
	if err != nil {
		return model.Sample{}, err
	}
	paramsJSON, err := model.CanonicalJSON(params)
	if err != nil {
		return model.Sample{}, err
	}
	return model.Sample{
		ID: id, Ordinal: ordinal, Label: label, Origin: "original-lines",
		MaterialID: material.ID, Offset: line.Offset, Length: line.Length,
		SHA256: sum, ParamsJSON: string(paramsJSON), CaseJSON: string(caseJSON),
		CreatedAt: createdAt,
	}, nil
}

func sanitize(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '-'
		}
	}, name)
	if name == "" {
		return "material"
	}
	return name
}

func SameBytes(a, b []byte) bool { return bytes.Equal(a, b) }

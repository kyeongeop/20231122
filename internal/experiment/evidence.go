package experiment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cacheleak.local/experiment/internal/model"
	"cacheleak.local/experiment/internal/store"
)

var safeNamePattern = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type EvidenceManager struct {
	runID   string
	dir     string
	store   *store.Store
	records []model.Evidence
}

func NewEvidenceManager(runID, dir string, st *store.Store) *EvidenceManager {
	return &EvidenceManager{runID: runID, dir: dir, store: st}
}

func (m *EvidenceManager) Dir() string {
	return m.dir
}

func (m *EvidenceManager) Records() []model.Evidence {
	return append([]model.Evidence(nil), m.records...)
}

func (m *EvidenceManager) WriteJSON(ctx context.Context, id, kind, description string, value any) (model.Evidence, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return model.Evidence{}, fmt.Errorf("encode %s: %w", id, err)
	}
	raw = append(raw, '\n')
	name := safeName(id) + ".json"
	return m.write(ctx, id, kind, description, name, raw)
}

func (m *EvidenceManager) WriteBytes(ctx context.Context, id, kind, description, fileName string, body []byte) (model.Evidence, error) {
	return m.write(ctx, id, kind, description, fileName, body)
}

func (m *EvidenceManager) CopyFile(ctx context.Context, id, kind, description, sourcePath string) (model.Evidence, error) {
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("read evidence source: %w", err)
	}
	return m.WriteBytes(ctx, id, kind, description, filepath.Base(sourcePath), body)
}

func (m *EvidenceManager) WriteManifest(ctx context.Context, extra any) (model.Evidence, error) {
	type manifest struct {
		Schema      string           `json:"schema"`
		RunID       string           `json:"run_id"`
		Generated   time.Time        `json:"generated_at"`
		Extra       any              `json:"extra,omitempty"`
		Objects     []model.Evidence `json:"objects"`
		ObjectCount int              `json:"object_count"`
	}
	records := append([]model.Evidence(nil), m.records...)
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	payload := manifest{
		Schema:      "cacheleak.evidence-manifest/v1",
		RunID:       m.runID,
		Generated:   time.Now().UTC(),
		Extra:       extra,
		Objects:     records,
		ObjectCount: len(records),
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return model.Evidence{}, err
	}
	raw = append(raw, '\n')
	return m.write(ctx, "manifest", "manifest", "SHA-256 manifest for every sealed evidence object", "manifest.json", raw)
}

func (m *EvidenceManager) write(ctx context.Context, id, kind, description, fileName string, body []byte) (model.Evidence, error) {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return model.Evidence{}, fmt.Errorf("create evidence directory: %w", err)
	}
	target := filepath.Join(m.dir, safeName(fileName))
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return model.Evidence{}, fmt.Errorf("write evidence temp file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return model.Evidence{}, fmt.Errorf("seal evidence file: %w", err)
	}
	if err := os.Chmod(target, 0o444); err != nil {
		return model.Evidence{}, fmt.Errorf("make evidence immutable: %w", err)
	}
	sum := sha256.Sum256(body)
	ev := model.Evidence{
		ID:          id,
		RunID:       m.runID,
		Kind:        kind,
		Path:        target,
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(body)),
		Immutable:   true,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}
	if err := m.store.AddEvidence(ctx, ev); err != nil {
		return model.Evidence{}, fmt.Errorf("record evidence %s: %w", id, err)
	}
	m.records = append(m.records, ev)
	return ev, nil
}

func safeName(value string) string {
	value = strings.TrimSpace(value)
	value = safeNamePattern.ReplaceAllString(value, "-")
	return strings.Trim(value, ".-")
}

func fileSHA(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

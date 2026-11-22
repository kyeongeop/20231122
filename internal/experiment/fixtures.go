package experiment

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"cacheleak.local/experiment/internal/model"
)

var knownExtensions = map[string]string{
	".txt":  "text/plain; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".png":  "image/png",
}

type Fixture struct {
	Snapshots []model.Snapshot
	Objects   []model.StoredObject
}

func NewFixture() Fixture {
	created := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	snapshots := []model.Snapshot{
		{ID: "snap-v1", Label: "release-2026.11.22-a", CreatedAt: created},
		{ID: "snap-v2", Label: "release-2026.11.22-b", CreatedAt: created.Add(time.Minute)},
	}
	objects := []model.StoredObject{
		newObject(snapshots[0], "/static/opaque.q7x", []byte(
			"CACHE-LEAK-SNAPSHOT=v1\nOBJECT=opaque.q7x\nPAYLOAD=alpha-0104\n",
		), created),
		newObject(snapshots[1], "/static/opaque.q7x", []byte(
			"CACHE-LEAK-SNAPSHOT=v2\nOBJECT=opaque.q7x\nPAYLOAD=beta-0208\n",
		), created.Add(time.Minute)),
		newObject(snapshots[0], "/static/tail.q7x", []byte(
			"CACHE-LEAK-SNAPSHOT=v1\nOBJECT=tail.q7x\nPAYLOAD=tail-alpha\n",
		), created),
		newObject(snapshots[1], "/static/tail.q7x", []byte(
			"CACHE-LEAK-SNAPSHOT=v2\nOBJECT=tail.q7x\nPAYLOAD=tail-beta\n",
		), created.Add(time.Minute)),
		newObject(snapshots[0], "/static/partial.q7x", []byte(
			"CACHE-LEAK-SNAPSHOT=v1\nOBJECT=partial.q7x\nPAYLOAD=exists-only-in-v1\n",
		), created),
	}
	return Fixture{Snapshots: snapshots, Objects: objects}
}

func newObject(snapshot model.Snapshot, logicalPath string, body []byte, at time.Time) model.StoredObject {
	sum := sha256.Sum256(body)
	ext := path.Ext(logicalPath)
	mimeType, known := knownExtensions[ext]
	if !known {
		mimeType = model.UnknownMIME
		if ext == model.UnknownExt {
			// The experiment's unknown extension is deliberately absent from the table.
			mimeType = model.UnknownMIME
		}
	}
	return model.StoredObject{
		Key:            snapshot.ID + ":" + logicalPath,
		SnapshotID:     snapshot.ID,
		Version:        snapshot.Label,
		LogicalPath:    logicalPath,
		FileName:       path.Base(logicalPath),
		Extension:      ext,
		KnownExtension: known,
		MIME:           mimeType,
		Size:           int64(len(body)),
		SHA256:         fmt.Sprintf("%x", sum),
		CapturedAt:     at.UTC(),
		Body:           append([]byte(nil), body...),
	}
}

func (f Fixture) Materialize(root string) ([]*SnapshotRuntime, error) {
	bySnapshot := make(map[string]*SnapshotRuntime, len(f.Snapshots))
	for _, snapshot := range f.Snapshots {
		snapshotRoot := filepath.Join(root, snapshot.ID)
		if err := os.MkdirAll(snapshotRoot, 0o755); err != nil {
			return nil, fmt.Errorf("create snapshot root: %w", err)
		}
		bySnapshot[snapshot.ID] = &SnapshotRuntime{
			Snapshot: snapshot,
			Root:     snapshotRoot,
			Objects:  make(map[string]model.StoredObject),
		}
	}
	for _, obj := range f.Objects {
		snap := bySnapshot[obj.SnapshotID]
		fileName := filepath.Join(snap.Root, filepath.FromSlash(strings.TrimPrefix(obj.LogicalPath, "/")))
		if err := os.MkdirAll(filepath.Dir(fileName), 0o755); err != nil {
			return nil, fmt.Errorf("create object directory: %w", err)
		}
		if err := os.WriteFile(fileName, obj.Body, 0o644); err != nil {
			return nil, fmt.Errorf("write temporary object %s: %w", obj.Key, err)
		}
		snap.Objects[obj.LogicalPath] = obj
	}
	return []*SnapshotRuntime{bySnapshot[f.Snapshots[0].ID], bySnapshot[f.Snapshots[1].ID]}, nil
}

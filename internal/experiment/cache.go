package experiment

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cacheleak.local/experiment/internal/model"
)

type SnapshotRuntime struct {
	Snapshot model.Snapshot
	Root     string
	Objects  map[string]model.StoredObject
}

type StaticCache struct {
	entries map[string]model.CacheEntry
	bodies  map[string][]byte
}

func NewStaticCache() *StaticCache {
	return &StaticCache{
		entries: make(map[string]model.CacheEntry),
		bodies:  make(map[string][]byte),
	}
}

func VulnerableCacheKey(method, requestPath string) string {
	return strings.ToUpper(method) + " " + requestPath
}

func (c *StaticCache) Lookup(key string) (model.CacheEntry, []byte, bool) {
	entry, ok := c.entries[key]
	if !ok {
		return model.CacheEntry{}, nil, false
	}
	body := append([]byte(nil), c.bodies[key]...)
	return entry, body, true
}

func (c *StaticCache) Store(key, snapshotID, version string, body []byte, at time.Time) model.CacheEntry {
	sum := sha256.Sum256(body)
	entry := model.CacheEntry{
		Key:        key,
		SnapshotID: snapshotID,
		Version:    version,
		SHA256:     fmt.Sprintf("%x", sum),
		Size:       int64(len(body)),
		StoredAt:   at.UTC(),
	}
	c.entries[key] = entry
	c.bodies[key] = append([]byte(nil), body...)
	return entry
}

func (c *StaticCache) Clear() {
	c.entries = make(map[string]model.CacheEntry)
	c.bodies = make(map[string][]byte)
}

func (c *StaticCache) State(selected, tempRoot string) model.StepState {
	state := model.StepState{
		CacheSize: len(c.entries),
		Cache:     make(map[string]model.CacheEntry, len(c.entries)),
		Selected:  selected,
	}
	for key, entry := range c.entries {
		state.Cache[key] = entry
	}
	if tempRoot != "" {
		_, err := os.Stat(tempRoot)
		state.TempRootPresent = err == nil
	}
	return state
}

func (c *StaticCache) Keys() []string {
	keys := make([]string, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type Harness struct {
	TempRoot  string
	Snapshots map[string]*SnapshotRuntime
	Cache     *StaticCache
}

func NewHarness(tempRoot string, snapshots []*SnapshotRuntime) *Harness {
	byID := make(map[string]*SnapshotRuntime, len(snapshots))
	for _, snap := range snapshots {
		byID[snap.Snapshot.ID] = snap
	}
	return &Harness{
		TempRoot:  tempRoot,
		Snapshots: byID,
		Cache:     NewStaticCache(),
	}
}

type ServeOutcome struct {
	Before model.StepState
	After  model.StepState
	Result model.StepResult
	Error  error
}

func (h *Harness) Serve(req model.RequestInput) ServeOutcome {
	out := ServeOutcome{Before: h.Cache.State(req.SnapshotID, h.TempRoot)}
	out.Result = model.StepResult{
		CacheKey:         VulnerableCacheKey(req.Method, req.Path),
		SelectedSnapshot: req.SnapshotID,
		CacheStatus:      "ERROR",
	}
	if req.Method != http.MethodGet {
		out.Result.StatusCode = http.StatusMethodNotAllowed
		out.Error = fmt.Errorf("unsupported method %q", req.Method)
		out.Result.Error = out.Error.Error()
		out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
		return out
	}
	snap, ok := h.Snapshots[req.SnapshotID]
	if !ok {
		out.Result.StatusCode = http.StatusNotFound
		out.Error = fmt.Errorf("unknown snapshot %q", req.SnapshotID)
		out.Result.Error = out.Error.Error()
		out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
		return out
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(req.Path, "/"))
	if cleanPath != req.Path {
		out.Result.StatusCode = http.StatusBadRequest
		out.Error = fmt.Errorf("non-canonical path %q", req.Path)
		out.Result.Error = out.Error.Error()
		out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
		return out
	}
	obj, ok := snap.Objects[req.Path]
	if !ok {
		out.Result.StatusCode = http.StatusNotFound
		out.Error = fmt.Errorf("object %q missing from snapshot %q", req.Path, req.SnapshotID)
		out.Result.Error = out.Error.Error()
		out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
		return out
	}

	out.Result.ExpectedSHA256 = obj.SHA256
	out.Result.MIME = obj.MIME
	entry, body, hit := h.Cache.Lookup(out.Result.CacheKey)
	if hit {
		out.Result.CacheStatus = "HIT"
		out.Result.ServedSnapshot = entry.SnapshotID
		out.Result.BodySHA256 = entry.SHA256
		out.Result.BodySize = int(entry.Size)
	} else {
		body, out.Error = os.ReadFile(filepath.Join(snap.Root, strings.TrimPrefix(req.Path, "/")))
		if out.Error != nil {
			out.Result.StatusCode = http.StatusInternalServerError
			out.Result.Error = out.Error.Error()
			out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
			return out
		}
		sum := sha256.Sum256(body)
		if fmt.Sprintf("%x", sum) != obj.SHA256 {
			out.Error = fmt.Errorf("snapshot file hash mismatch for %s", obj.Key)
			out.Result.StatusCode = http.StatusInternalServerError
			out.Result.Error = out.Error.Error()
			out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
			return out
		}
		entry = h.Cache.Store(out.Result.CacheKey, snap.Snapshot.ID, obj.Version, body, time.Now().UTC())
		out.Result.CacheStatus = "MISS"
		out.Result.ServedSnapshot = entry.SnapshotID
		out.Result.BodySHA256 = entry.SHA256
		out.Result.BodySize = int(entry.Size)
	}
	out.Result.StatusCode = http.StatusOK
	out.Result.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	out.Result.Leaked = out.Result.BodySHA256 != out.Result.ExpectedSHA256
	out.Result.StaleByVersion = out.Result.ServedSnapshot != req.SnapshotID
	out.After = h.Cache.State(req.SnapshotID, h.TempRoot)
	return out
}

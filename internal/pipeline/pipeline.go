// Package pipeline orchestrates the reviewable LFI ingestion: it discovers
// evidence objects in two versioned snapshots, parses each one independently
// so a single failure never aborts the run, persists correlated records to
// SQLite, and guarantees temporary state is removed at the end.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"lfireview/internal/model"
	"lfireview/internal/parse"
	"lfireview/internal/storage"
)

// Config configures a pipeline run.
type Config struct {
	// SnapshotV1 is the directory holding legacy v1 objects.
	SnapshotV1 string
	// SnapshotV2 is the directory holding current v2 objects.
	SnapshotV2 string
	// DBPath is the review database. An empty path uses a temp database
	// that is deleted when the run is cleaned up.
	DBPath string
}

// ObjectResult summarizes processing of one snapshot object.
type ObjectResult struct {
	Version string
	Object  string
	Status  model.ParseStatus
	Error   string
}

// Report is the outcome of a run.
type Report struct {
	RunID       string
	DBPath      string
	TempDB      bool
	Snapshots   map[string]string
	Results     []ObjectResult
	Truncated   []storage.TruncatedRow
	Total       int
	Failed      int
	TruncatedN  int
	CleanedUp   []string
	TempWorkDir string
}

type objectRef struct {
	version string
	dir     string
	name    string
}

// Run executes one full ingestion. It always returns a non-nil report
// describing what happened; an error is returned only for fatal setup
// failures such as missing snapshots.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	report := &Report{Snapshots: map[string]string{}}

	snapshots := []struct {
		version string
		dir     string
	}{
		{parse.VersionV1, cfg.SnapshotV1},
		{parse.VersionV2, cfg.SnapshotV2},
	}

	var refs []objectRef
	for _, snap := range snapshots {
		info, err := os.Stat(snap.dir)
		if err != nil {
			return report, fmt.Errorf("snapshot %s not readable: %w", snap.version, err)
		}
		if !info.IsDir() {
			return report, fmt.Errorf("snapshot %s is not a directory: %s", snap.version, snap.dir)
		}
		report.Snapshots[snap.version] = snap.dir
		objects, err := discover(snap.dir)
		if err != nil {
			return report, fmt.Errorf("discover %s: %w", snap.version, err)
		}
		for _, name := range objects {
			refs = append(refs, objectRef{version: snap.version, dir: snap.dir, name: name})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].version != refs[j].version {
			return refs[i].version < refs[j].version
		}
		return refs[i].name < refs[j].name
	})

	workDir, err := os.MkdirTemp("", "lfireview-work-")
	if err != nil {
		return report, fmt.Errorf("create work dir: %w", err)
	}
	report.TempWorkDir = workDir

	tempDB := cfg.DBPath == ""
	dbPath := cfg.DBPath
	if tempDB {
		dbPath = filepath.Join(workDir, "review.sqlite")
	}
	report.DBPath = dbPath
	report.TempDB = tempDB

	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		cleanupTemp(report, workDir, nil)
		return report, err
	}

	runID := time.Now().UTC().Format("run-20060102T150405.000000000Z")
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if err := store.BeginRun(ctx, runID, started); err != nil {
		store.Close(ctx)
		cleanupTemp(report, workDir, nil)
		return report, err
	}
	report.RunID = runID

	for _, ref := range refs {
		result := processOne(ctx, store, runID, ref)
		report.Results = append(report.Results, result)
		report.Total++
		if result.Status == model.StatusMalformed {
			report.Failed++
		}
		if result.Status == model.StatusTruncated {
			report.TruncatedN++
		}
	}

	truncated, err := store.QueryTruncated(ctx)
	if err == nil {
		report.Truncated = truncated
	}

	status := "completed"
	if report.Failed > 0 {
		status = "completed_with_errors"
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	if err := store.FinishRun(ctx, runID, finished, status, report.Total, report.Failed); err != nil {
		store.Close(ctx)
		cleanupTemp(report, workDir, nil)
		return report, err
	}

	if err := store.Close(ctx); err != nil {
		cleanupTemp(report, workDir, nil)
		return report, err
	}
	if tempDB {
		report.CleanedUp = append(report.CleanedUp, removeAndReport(store, dbPath)...)
	}
	cleanupTemp(report, workDir, nil)
	return report, nil
}

func removeAndReport(store *storage.Store, dbPath string) []string {
	var existed []string
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			existed = append(existed, dbPath+suffix)
		}
	}
	if err := store.Remove(); err != nil {
		return nil
	}
	return existed
}

// processOne handles a single object; any error is converted into a result so
// the loop continues with the remaining objects.
func processOne(ctx context.Context, store *storage.Store, runID string, ref objectRef) ObjectResult {
	result := ObjectResult{Version: ref.version, Object: ref.name}

	data, err := os.ReadFile(filepath.Join(ref.dir, ref.name))
	if err != nil {
		result.Status = model.StatusMalformed
		result.Error = "read: " + err.Error()
		return result
	}

	rec, decodeErr := parse.Decode(ref.version, ref.name, data)
	if decodeErr != nil {
		rec.Status = model.StatusMalformed
		rec.ParseError = decodeErr.Error()
	}

	if _, err := store.InsertRecord(ctx, runID,
		time.Now().UTC().Format(time.RFC3339Nano), rec); err != nil {
		result.Status = model.StatusMalformed
		result.Error = "persist: " + err.Error()
		return result
	}

	result.Status = rec.Status
	result.Error = rec.ParseError
	return result
}

func discover(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func cleanupTemp(report *Report, workDir string, extraFiles []string) {
	for _, name := range extraFiles {
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			continue
		}
		if _, err := os.Stat(name); os.IsNotExist(err) {
			report.CleanedUp = append(report.CleanedUp, name)
		}
	}
	if err := os.RemoveAll(workDir); err == nil {
		if _, err := os.Stat(workDir); os.IsNotExist(err) {
			report.CleanedUp = append(report.CleanedUp, workDir)
		}
	}
}

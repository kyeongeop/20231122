package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"serrfix/internal/model"
	"serrfix/internal/store"
	"serrfix/internal/workspace"
)

type InitOptions struct {
	OriginalPath string
}

type InitResult struct {
	AlreadyInitialized bool   `json:"already_initialized"`
	Workspace          string `json:"workspace"`
	MaterialID         string `json:"material_id"`
	SnapshotPath       string `json:"snapshot_path"`
	OriginalPath       string `json:"original_path"`
	OriginalSHA256     string `json:"original_sha256"`
	OriginalSize       int64  `json:"original_size"`
	CapturedAt         string `json:"captured_at"`
	Samples            int    `json:"samples"`
}

func (a *App) Init(opts InitOptions) (InitResult, error) {
	if opts.OriginalPath == "" {
		return InitResult{}, fmt.Errorf("--original is required")
	}
	source, err := filepath.Abs(opts.OriginalPath)
	if err != nil {
		return InitResult{}, err
	}
	initialized, err := a.initialized()
	if err != nil {
		return InitResult{}, err
	}
	if initialized {
		return a.existingInitResult()
	}

	capturedAt := a.now()
	snap, err := a.WS.SnapshotMaterial(source, "original", capturedAt)
	if err != nil {
		return InitResult{}, err
	}
	if err := workspace.CheckMaterial(a.WS.Root, snap.Material); err != nil {
		return InitResult{}, fmt.Errorf("snapshot verification: %w", err)
	}

	existing, err := a.DB.GetMaterial(snap.Material.ID)
	if err == nil {
		if existing.SHA256 != snap.Material.SHA256 || existing.Size != snap.Material.Size {
			return InitResult{}, fmt.Errorf("material id collision for %s", snap.Material.ID)
		}
	} else if err != store.ErrNotFound {
		return InitResult{}, err
	} else if err := a.DB.AddMaterial(snap.Material); err != nil {
		return InitResult{}, err
	}

	data, err := os.ReadFile(snap.Path)
	if err != nil {
		return InitResult{}, err
	}
	lines := workspace.SplitLines(data)
	if len(lines) == 0 {
		return InitResult{}, fmt.Errorf("original material has no non-empty attack samples")
	}
	added := 0
	for i, line := range lines {
		ordinal := i + 1
		command := fmt.Sprintf("serrfix rerun --workspace %q --sample <sample-id>",
			a.WS.Root)
		sample, err := workspace.BuildSample(line, snap.Material, ordinal, capturedAt, command)
		if err != nil {
			return InitResult{}, err
		}
		if _, err := a.DB.GetSample(sample.ID); err == nil {
			continue
		} else if err != store.ErrNotFound {
			return InitResult{}, err
		}
		if err := a.DB.AddSample(sample); err != nil {
			return InitResult{}, err
		}
		added++
	}
	if err := a.DB.SetMeta("schema_version", "1", model.Timestamp(capturedAt)); err != nil {
		return InitResult{}, err
	}
	if err := a.DB.SetMeta("original_material_id", snap.Material.ID, model.Timestamp(capturedAt)); err != nil {
		return InitResult{}, err
	}
	if err := a.DB.SetMeta("initialized_at", model.Timestamp(capturedAt), model.Timestamp(capturedAt)); err != nil {
		return InitResult{}, err
	}
	if err := a.DB.AddEvent(model.Timestamp(capturedAt), "workspace_initialized", "", "",
		fmt.Sprintf(`{"material_id":%q,"sha256":%q,"samples_added":%d}`,
			snap.Material.ID, snap.Material.SHA256, added)); err != nil {
		return InitResult{}, err
	}
	return a.existingInitResultWith(false)
}

func (a *App) existingInitResult() (InitResult, error) {
	return a.existingInitResultWith(true)
}

func (a *App) existingInitResultWith(already bool) (InitResult, error) {
	materialID, err := a.DB.GetMeta("original_material_id")
	if err != nil {
		return InitResult{}, err
	}
	m, err := a.DB.GetMaterial(materialID)
	if err != nil {
		return InitResult{}, err
	}
	n, err := a.DB.CountSamples()
	if err != nil {
		return InitResult{}, err
	}
	captured, err := a.DB.GetMeta("initialized_at")
	if err != nil {
		return InitResult{}, err
	}
	if err := workspace.CheckMaterial(a.WS.Root, m); err != nil {
		return InitResult{}, fmt.Errorf("stored original material is invalid: %w", err)
	}
	return InitResult{
		AlreadyInitialized: already,
		Workspace:          a.WS.Root,
		MaterialID:         m.ID,
		SnapshotPath:       m.SnapshotPath,
		OriginalPath:       m.SourcePath,
		OriginalSHA256:     m.SHA256,
		OriginalSize:       m.Size,
		CapturedAt:         captured,
		Samples:            n,
	}, nil
}

func parseAt(s string) (time.Time, error) {
	return model.ParseTimestamp(s)
}

package inspect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (s *Store) CleanupTemporary(ctx context.Context) (int, error) {
	states, err := s.temporaryStates(ctx)
	if err != nil {
		return 0, err
	}
	allowedRoots := []string{
		filepath.Join(os.TempDir(), "webhook-provenance"),
		filepath.Join(filepath.Dir(s.dbPath), "tmp"),
	}
	var failures []error
	removed := 0
	for _, state := range states {
		path, err := filepath.Abs(state.Path)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !withinAny(path, allowedRoots) {
			failures = append(failures, fmt.Errorf("refuse to remove path outside temporary roots: %s", path))
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			failures = append(failures, err)
			continue
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM temp_state WHERE id = ?`, state.ID); err != nil {
			failures = append(failures, err)
			continue
		}
		removed++
	}
	if len(failures) > 0 {
		return removed, errors.Join(failures...)
	}
	_ = s.recordOperation(ctx, "", "cleanup", "ok",
		fmt.Sprintf("已清理 %d 个临时复验目录；正式证据未删除。", removed))
	return removed, nil
}

func withinAny(path string, roots []string) bool {
	for _, root := range roots {
		cleanRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(cleanRoot, path)
		if err != nil {
			continue
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

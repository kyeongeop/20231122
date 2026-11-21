package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"auditfix/internal/db"
)

func Restore(ctx context.Context, bundleDir, targetDB string, force bool) error {
	report, err := Verify(ctx, bundleDir, VerifyOptions{})
	if err != nil {
		return fmt.Errorf("refusing to restore invalid bundle: %w", err)
	}
	source := filepath.Join(bundleDir, DatabaseName)
	target, err := filepath.Abs(targetDB)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil && !force {
		return fmt.Errorf("target database %q already exists", targetDB)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".auditfix-restore-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := copyFile(source, tempPath); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, 0o644); err != nil {
		return err
	}
	store, err := db.OpenReadOnly(tempPath)
	if err != nil {
		return fmt.Errorf("open restored database: %w", err)
	}
	_, err = store.GetRun(ctx, report.RunID)
	store.Close()
	if err != nil {
		return fmt.Errorf("restored database is missing run %s: %w", report.RunID, err)
	}
	if err := os.Rename(tempPath, target); err != nil {
		return err
	}
	_ = os.Remove(target + "-wal")
	_ = os.Remove(target + "-shm")
	return nil
}

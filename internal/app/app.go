package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"serrfix/internal/store"
	"serrfix/internal/workspace"
)

type App struct {
	WS  workspace.Workspace
	DB  *store.DB
	Now func() time.Time
	Out io.Writer
	Err io.Writer
}

func Open(root string, out, errOut io.Writer) (*App, error) {
	ws, err := workspace.Open(root)
	if err != nil {
		return nil, err
	}
	if err := ws.Ensure(); err != nil {
		return nil, err
	}
	db, err := ws.OpenDB()
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	return &App{
		WS: ws, DB: db, Out: out, Err: errOut,
		Now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (a *App) Close() error { return a.DB.Close() }

func (a *App) now() time.Time { return a.Now().UTC() }

func (a *App) rel(path string) string {
	rel, err := filepath.Rel(a.WS.Root, path)
	if err != nil {
		return path
	}
	return rel
}

func (a *App) initialized() (bool, error) {
	_, err := a.DB.GetMeta("initialized_at")
	if err == nil {
		return true, nil
	}
	if err == store.ErrNotFound {
		return false, nil
	}
	return false, err
}

func (a *App) atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func (a *App) requireInitialized() error {
	ok, err := a.initialized()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("workspace is not initialized; run: serrfix init --workspace %s --original <file>", a.WS.Root)
	}
	return nil
}

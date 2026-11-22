package tempstate

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Manager 为每条记录分配独立的临时工作目录，并在结束时清理。
type Manager struct {
	root string
	mu   sync.Mutex
	live map[string]string
}

// New 在 base 下创建一个托管根目录。
func New(base string) (*Manager, error) {
	root, err := os.MkdirTemp(base, "whitelist-audit-*")
	if err != nil {
		return nil, fmt.Errorf("create temp root: %w", err)
	}
	return &Manager{root: root, live: map[string]string{}}, nil
}

// Root 返回托管根目录，便于最终校验清理结果。
func (m *Manager) Root() string { return m.root }

// Allocate 为记录创建独立工作目录，返回目录与清理函数。
func (m *Manager) Allocate(recordID string) (string, func(), error) {
	dir := filepath.Join(m.root, "rec-"+sanitize(recordID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("mkdir workdir: %w", err)
	}
	marker := filepath.Join(dir, "state.tmp")
	if err := os.WriteFile(marker, []byte(recordID), 0o600); err != nil {
		return "", nil, fmt.Errorf("write state marker: %w", err)
	}
	m.mu.Lock()
	m.live[recordID] = dir
	m.mu.Unlock()

	cleanup := func() {
		_ = os.RemoveAll(dir)
		m.mu.Lock()
		delete(m.live, recordID)
		m.mu.Unlock()
	}
	return dir, cleanup, nil
}

// CleanupAll 在批处理结束时清理托管根目录下的全部临时状态。
func (m *Manager) CleanupAll() error {
	return os.RemoveAll(m.root)
}

// LiveCount 返回仍未清理的记录工作目录数量。
func (m *Manager) LiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

// RootExists 报告托管根目录是否仍存在（清理后应为 false）。
func (m *Manager) RootExists() bool {
	_, err := os.Stat(m.root)
	return err == nil
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, byte(r))
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

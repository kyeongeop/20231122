package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLog appends one JSON object per event. The digest of every line a
// run produced is stored in the evidence record, so the log itself becomes
// tamper-evident evidence linked to the database row.
type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenAudit opens (creating if needed) the audit log at path.
func OpenAudit(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f, path: path}, nil
}

// Path returns the log file path recorded in evidence rows.
func (a *AuditLog) Path() string { return a.path }

// Close flushes and closes the log file.
func (a *AuditLog) Close() error { return a.f.Close() }

// Event appends one structured event and returns its line digest.
func (a *AuditLog) Event(event string, kv ...any) (string, error) {
	m := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": event}
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(append(b, '\n')); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log adapts AuditLog to decomp.Logger.
func (a *AuditLog) Log(event string, kv ...any) {
	_, _ = a.Event(event, kv...)
}

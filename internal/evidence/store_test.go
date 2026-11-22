package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPutVerifyAndTamperDetection(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := store.Put("fuzz-input", "text/plain", []byte("artifact"))
	if err != nil {
		t.Fatalf("Put first: %v", err)
	}
	second, err := store.Put("fuzz-input", "text/plain", []byte("artifact"))
	if err != nil {
		t.Fatalf("Put second: %v", err)
	}
	if first.SHA256 != second.SHA256 || first.RelativePath != second.RelativePath {
		t.Fatalf("content addressing mismatch: %#v %#v", first, second)
	}
	if err := store.Verify(first); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	path := filepath.Join(root, first.RelativePath)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("evidence is writable: %v", info.Mode())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := store.Verify(first); err == nil {
		t.Fatal("expected hash or size mismatch")
	}
}

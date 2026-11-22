package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"seedreview/internal/model"
)

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "sha256"), 0o755); err != nil {
		return nil, fmt.Errorf("create evidence root: %w", err)
	}
	return &Store{root: abs}, nil
}

func (s *Store) Root() string {
	return s.root
}

func (s *Store) Put(kind, mediaType string, data []byte) (model.Evidence, error) {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	relative := filepath.Join("sha256", hash[:2], hash)
	destination := filepath.Join(s.root, relative)
	now := time.Now().UTC()

	if info, err := os.Stat(destination); err == nil {
		if info.Size() != int64(len(data)) {
			return model.Evidence{}, fmt.Errorf("evidence collision for %s", hash)
		}
		return model.Evidence{
			SHA256: hash, Kind: kind, RelativePath: relative,
			Size: info.Size(), MediaType: mediaType, CreatedAt: now,
		}, nil
	} else if !os.IsNotExist(err) {
		return model.Evidence{}, fmt.Errorf("stat evidence %s: %w", hash, err)
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return model.Evidence{}, fmt.Errorf("create evidence shard: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".seedreview-*")
	if err != nil {
		return model.Evidence{}, fmt.Errorf("create evidence temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return model.Evidence{}, fmt.Errorf("write evidence: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return model.Evidence{}, fmt.Errorf("sync evidence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return model.Evidence{}, fmt.Errorf("close evidence: %w", err)
	}
	if err := os.Chmod(tmpName, 0o444); err != nil {
		return model.Evidence{}, fmt.Errorf("protect evidence: %w", err)
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return model.Evidence{}, fmt.Errorf("commit evidence: %w", err)
	}

	return model.Evidence{
		SHA256: hash, Kind: kind, RelativePath: relative,
		Size: int64(len(data)), MediaType: mediaType, CreatedAt: now,
	}, nil
}

func (s *Store) PutFile(kind, mediaType, path string) (model.Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Evidence{}, fmt.Errorf("read %s: %w", path, err)
	}
	return s.Put(kind, mediaType, data)
}

func (s *Store) Read(record model.Evidence) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.root, record.RelativePath))
	if err != nil {
		return nil, fmt.Errorf("read evidence %s: %w", record.SHA256, err)
	}
	return data, nil
}

func (s *Store) Verify(record model.Evidence) error {
	data, err := s.Read(record)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, record.SHA256) {
		return fmt.Errorf("evidence hash mismatch for %s: got %s", record.SHA256, actual)
	}
	if int64(len(data)) != record.Size {
		return fmt.Errorf("evidence size mismatch for %s: got %d want %d", record.SHA256, len(data), record.Size)
	}
	return nil
}

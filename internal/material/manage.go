// Package material owns the immutable original material and the working
// corpus. The original is written once, chmod read-only and hash-pinned in
// SQLite; every replay touches only copies under the working directory.
package material

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"krfix/internal/store"
	gen "krfix/target/material"
)

// Layout groups the on-disk paths of a krfix workspace.
type Layout struct {
	Root        string // .krfix
	OriginalDir string // read-only sealed original material
	CorpusDir   string // per-sample replay copies (writable)
	EvidenceDir string // captured logs and export bundles
	DBPath      string
	BuildDir    string
}

// NewLayout resolves the standard workspace layout under workRoot.
func NewLayout(workRoot string) Layout {
	root := filepath.Join(workRoot, ".krfix")
	return Layout{
		Root:        root,
		OriginalDir: filepath.Join(root, "original"),
		CorpusDir:   filepath.Join(root, "corpus"),
		EvidenceDir: filepath.Join(root, "evidence"),
		DBPath:      filepath.Join(root, "krfix.db"),
		BuildDir:    filepath.Join(root, "build"),
	}
}

const (
	originalName = "original_kr_blob.bin"
	manifestName = "ORIGINAL_MANIFEST.txt"
)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SHA256Hex exposes the digest helper used by CLI output.
func SHA256Hex(b []byte) string { return sha(b) }

// SealOriginal generates the canonical original material, writes it once as a
// read-only file and pins its hash in SQLite. Re-sealing is refused while the
// file exists, so the unmodified original is always retained.
func SealOriginal(ctx context.Context, l Layout, db *sql.DB) ([]byte, []gen.Anchor, error) {
	if err := os.MkdirAll(l.OriginalDir, 0o755); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(l.OriginalDir, originalName)
	if _, err := os.Stat(path); err == nil {
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, nil, rerr
		}
		anchors, lerr := gen.Locate(raw)
		if lerr != nil {
			return nil, nil, lerr
		}
		return raw, anchors, fmt.Errorf("original material already sealed at %s (refusing to overwrite)", path)
	}

	// Baseline frame: key rotation was committed (server epoch == attestation
	// epoch == 4), and the frame was sealed under the current key.
	var cipher, tag [32]byte
	for i := range cipher {
		cipher[i] = byte(0xA0 ^ i)
		tag[i] = byte(0x50 + i)
	}
	raw := gen.Build(7 /* key id */, 4 /* server epoch */, 4, /* client epoch */
		4 /* attest epoch */, cipher, tag)
	anchors, err := gen.Locate(raw)
	if err != nil {
		return nil, nil, err
	}

	if err := os.WriteFile(path, raw, 0o444); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o444); err != nil { // read-only, even for owner
		return nil, nil, err
	}
	digest := sha(raw)
	manifest := fmt.Sprintf(
		"file=%s\nsha256=%s\nsize_bytes=%d\nsealed_at_utc=%s\nmode=0444\n",
		path, digest, len(raw), store.NowUTC())
	if err := os.WriteFile(filepath.Join(l.OriginalDir, manifestName),
		[]byte(manifest), 0o444); err != nil {
		return nil, nil, err
	}

	if err := store.SetMeta(ctx, db, "original_path", path); err != nil {
		return nil, nil, err
	}
	if err := store.SetMeta(ctx, db, "original_sha256", digest); err != nil {
		return nil, nil, err
	}
	if err := store.SetMeta(ctx, db, "original_size", fmt.Sprintf("%d", len(raw))); err != nil {
		return nil, nil, err
	}
	for _, a := range anchors {
		if err := store.InsertAnchor(ctx, db, a.Index, a.Magic, a.Name,
			a.Offset, a.Length); err != nil {
			return nil, nil, err
		}
	}
	return raw, anchors, nil
}

// VerifyOriginal re-hashes the sealed file and compares it with the pinned
// digest. A mismatch means the original material can no longer be trusted.
func VerifyOriginal(ctx context.Context, l Layout, db *sql.DB) error {
	path := filepath.Join(l.OriginalDir, originalName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pinned, err := store.GetMeta(ctx, db, "original_sha256")
	if err != nil {
		return fmt.Errorf("no pinned hash found; run 'krfix init' first: %w", err)
	}
	if got := sha(raw); got != pinned {
		return fmt.Errorf("original material tampered: pinned=%s actual=%s", pinned, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o444 {
		return fmt.Errorf("original file mode drifted: %o", info.Mode().Perm())
	}
	return nil
}

// PinnedHash returns the hash recorded at seal time.
func PinnedHash(ctx context.Context, l Layout, db *sql.DB) (string, error) {
	return store.GetMeta(ctx, db, "original_sha256")
}

// ImportSample copies one corpus input into the working corpus (never the
// read-only original directory), locates its three anchors and persists raw
// offsets plus epoch fields so acceptance can cite concrete byte positions.
func ImportSample(ctx context.Context, l Layout, db *sql.DB,
	name, kind string, content []byte) (*store.Sample, error) {
	if kind != "attack" && kind != "benign" {
		return nil, fmt.Errorf("kind must be attack or benign, got %q", kind)
	}
	anchors, err := gen.Locate(content)
	if err != nil {
		return nil, fmt.Errorf("sample %q: %w", name, err)
	}
	frame, err := gen.Parse(content, anchors)
	if err != nil {
		return nil, fmt.Errorf("sample %q: %w", name, err)
	}
	if err := os.MkdirAll(l.CorpusDir, 0o755); err != nil {
		return nil, err
	}
	dst := filepath.Join(l.CorpusDir, name+".bin")
	if err := os.WriteFile(dst, content, 0o644); err != nil {
		return nil, err
	}
	s := store.Sample{
		Name:        name,
		Kind:        kind,
		RawPath:     dst,
		SHA256:      sha(content),
		Size:        int64(len(content)),
		ClientEpoch: int64(frame.ClientEpoch),
		ServerEpoch: int64(frame.ServerEpoch),
		AttestEpoch: int64(frame.AttestEpoch),
	}
	for i, a := range anchors {
		s.AnchorOffsets[i] = a.Offset
	}
	id, err := store.InsertSample(ctx, db, s)
	if err != nil {
		return nil, err
	}
	s.ID = id
	return &s, nil
}

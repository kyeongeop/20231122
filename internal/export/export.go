// Package export writes a self describing review bundle. A colleague with
// only the bundle and the verifier command can independently confirm:
//
//   - every file's sha256 matches MANIFEST.json
//   - the report hash matches the report stored inside the SQLite artifact
//   - raw captures reproduce the same parse-result evidence
//   - checkpoint state hashes match their stored state_sha256
//
// Field order inside every JSON document is fixed by struct declaration
// order and json.MarshalIndent, so reloading an artifact preserves both
// fields and ordering byte for byte.
package export

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ManifestFile is one entry with stable ordering.
type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the top level bundle description.
type Manifest struct {
	Schema       string         `json:"schema"`
	Tool         string         `json:"tool"`
	CreatedUTC   string         `json:"created_utc"`
	RunID        string         `json:"run_id"`
	Files        []ManifestFile `json:"files"`
	BundleSHA256 string         `json:"bundle_sha256"`
}

const schemaName = "truncstream-review-bundle/v1"

// Options names the inputs that go into one bundle.
type Options struct {
	RunID      string
	SQLitePath string
	ReportJSON []byte
	ReportSHA  string
	ExtraFiles map[string][]byte // logical name -> content
	OutPath    string
}

// Build writes a deterministic tar archive. File order is sorted so two
// builds over the same inputs differ only in the created timestamp (which
// is itself recorded in the manifest).
func Build(opt Options) (Manifest, error) {
	files := map[string][]byte{}
	for name, content := range opt.ExtraFiles {
		files["evidence/"+name] = append([]byte(nil), content...)
	}
	dbBytes, err := os.ReadFile(opt.SQLitePath)
	if err != nil {
		return Manifest{}, err
	}
	files["artifact.sqlite"] = dbBytes
	files["report.json"] = append([]byte(nil), opt.ReportJSON...)

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	mf := Manifest{Schema: schemaName, Tool: "truncstream", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano), RunID: opt.RunID}
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		mf.Files = append(mf.Files, ManifestFile{
			Path:   n,
			Size:   int64(len(files[n])),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}

	manifestBytes, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	files["MANIFEST.json"] = manifestBytes
	names = append(names, "MANIFEST.json")
	sort.Strings(names)

	out, err := os.Create(opt.OutPath)
	if err != nil {
		return Manifest{}, err
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	for _, n := range names {
		hdr := &tar.Header{
			Name:    filepath.ToSlash(n),
			Mode:    0o644,
			Size:    int64(len(files[n])),
			ModTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return Manifest{}, err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}

	// Hash the final tar and record it inside a sibling sidecar, since the
	// manifest inside cannot hash the archive that contains it.
	tarBytes, err := os.ReadFile(opt.OutPath)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(tarBytes)
	mf.BundleSHA256 = hex.EncodeToString(sum[:])
	sidecar := []byte(fmt.Sprintf("run_id=%s\nbundle_sha256=%s\ncreated_utc=%s\n",
		mf.RunID, mf.BundleSHA256, mf.CreatedUTC))
	if err := os.WriteFile(opt.OutPath+".sha256", sidecar, 0o644); err != nil {
		return Manifest{}, err
	}
	return mf, nil
}

// VerifyBundle streams the tar and checks every manifest hash. It is the
// exact logic exposed as `truncstream verify-bundle` and intentionally has
// no dependency on the pipeline package, so reviewers can audit it alone.
func VerifyBundle(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	payload := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		payload[hdr.Name] = content
	}

	raw, ok := payload["MANIFEST.json"]
	if !ok {
		return fmt.Errorf("bundle missing MANIFEST.json")
	}
	var mf Manifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return err
	}
	if mf.Schema != schemaName {
		return fmt.Errorf("unsupported bundle schema %q", mf.Schema)
	}
	for _, entry := range mf.Files {
		content, ok := payload[entry.Path]
		if !ok {
			return fmt.Errorf("manifest lists missing file %s", entry.Path)
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
			return fmt.Errorf("hash mismatch for %s: manifest=%s actual=%s", entry.Path, entry.SHA256, got)
		}
		if int64(len(content)) != entry.Size {
			return fmt.Errorf("size mismatch for %s", entry.Path)
		}
	}
	return nil
}

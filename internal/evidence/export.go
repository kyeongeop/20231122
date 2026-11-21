// Package evidence renders per-sample export bundles and side-by-side
// comparisons of the vulnerable and fixed replays.
package evidence

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SampleReport is the exportable per-sample verdict record. All offsets are
// raw byte offsets into the unmodified original-format frame.
type SampleReport struct {
	ExportedAtUTC string         `json:"exported_at_utc"`
	Sample        SampleSection  `json:"sample"`
	Anchors       []AnchorRow    `json:"anchors"`
	Replays       map[string]Run `json:"replays"`
	Comparison    Comparison     `json:"comparison"`
	Evidence      []EvidenceRow  `json:"evidence_files"`
}

type SampleSection struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	RawPath     string `json:"raw_path"`
	ServerEpoch int64  `json:"server_epoch"`
	ClientEpoch int64  `json:"client_epoch"`
	AttestEpoch int64  `json:"attest_epoch"`
}

type AnchorRow struct {
	AnchorIndex int    `json:"anchor_index"`
	Magic       string `json:"magic"`
	Name        string `json:"name"`
	RawOffset   int64  `json:"raw_offset"`
	Length      int64  `json:"length"`
	LocatedAt   string `json:"located_at_utc"`
}

type Run struct {
	State         string `json:"job_state"`
	Attempts      int    `json:"attempts"`
	ExitCode      *int64 `json:"exit_code"`
	VerdictCode   *int64 `json:"verdict_code"`
	VerdictLabel  string `json:"verdict_label"`
	DurationNS    *int64 `json:"duration_ns"`
	StartedAtUTC  string `json:"started_at_utc"`
	FinishedAtUTC string `json:"finished_at_utc"`
}

type Comparison struct {
	FixedConfirmsBug bool   `json:"fixed_confirms_bug"`
	Summary          string `json:"summary"`
}

type EvidenceRow struct {
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Note          string `json:"note"`
	CapturedAtUTC string `json:"captured_at_utc"`
}

// BuildReport queries SQLite for one sample and assembles its report.
func BuildReport(ctx context.Context, db *sql.DB, name string) (*SampleReport, error) {
	rep := &SampleReport{
		ExportedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Replays:       map[string]Run{},
	}

	row := db.QueryRowContext(ctx,
		`SELECT id,name,kind,raw_path,sha256,size_bytes,
		        client_epoch,server_epoch,attest_epoch
		 FROM samples WHERE name=?`, name)
	var sampleID int64
	var s SampleSection
	if err := row.Scan(&sampleID, &s.Name, &s.Kind, &s.RawPath, &s.SHA256,
		&s.SizeBytes, &s.ClientEpoch, &s.ServerEpoch, &s.AttestEpoch); err != nil {
		return nil, err
	}
	rep.Sample = s

	arows, err := db.QueryContext(ctx,
		`SELECT anchor_index,magic,name,raw_offset,length,located_at_utc
		 FROM anchors ORDER BY anchor_index`)
	if err != nil {
		return nil, err
	}
	for arows.Next() {
		var a AnchorRow
		if err := arows.Scan(&a.AnchorIndex, &a.Magic, &a.Name,
			&a.RawOffset, &a.Length, &a.LocatedAt); err != nil {
			arows.Close()
			return nil, err
		}
		rep.Anchors = append(rep.Anchors, a)
	}
	arows.Close()

	for _, phase := range []string{"vuln", "fixed"} {
		r, err := queryRun(ctx, db, sampleID, phase)
		if err != nil {
			return nil, err
		}
		rep.Replays[phase] = r
	}
	rep.Comparison = compare(rep.Replays["vuln"], rep.Replays["fixed"], s.Kind)

	erows, err := db.QueryContext(ctx,
		`SELECT kind,path,sha256,note,captured_at_utc
		 FROM evidence WHERE sample_id=? ORDER BY captured_at_utc`, sampleID)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var e EvidenceRow
		if err := erows.Scan(&e.Kind, &e.Path, &e.SHA256, &e.Note,
			&e.CapturedAtUTC); err != nil {
			return nil, err
		}
		rep.Evidence = append(rep.Evidence, e)
	}
	return rep, erows.Err()
}

func queryRun(ctx context.Context, db *sql.DB, sampleID int64, phase string) (Run, error) {
	row := db.QueryRowContext(ctx,
		`SELECT j.state,j.attempts,r.exit_code,r.verdict_code,
		        COALESCE(r.verdict_label,''),r.duration_ns,
		        COALESCE(r.started_at_utc,''),COALESCE(r.finished_at_utc,'')
		 FROM jobs j LEFT JOIN runs r ON r.job_id=j.id
		 WHERE j.sample_id=? AND j.phase=?
		 ORDER BY r.id DESC LIMIT 1`, sampleID, phase)
	var r Run
	err := row.Scan(&r.State, &r.Attempts, &r.ExitCode, &r.VerdictCode,
		&r.VerdictLabel, &r.DurationNS, &r.StartedAtUTC, &r.FinishedAtUTC)
	if err == sql.ErrNoRows {
		return Run{State: "missing"}, nil
	}
	return r, err
}

func compare(vuln, fixed Run, kind string) Comparison {
	c := Comparison{}
	vulnBug := vuln.VerdictLabel == "ROTATION_FAILURE_REPRODUCED"
	fixedReject := fixed.VerdictLabel == "STALE_KEY_REJECTED"
	switch {
	case kind == "attack" && vulnBug && fixedReject:
		c.FixedConfirmsBug = true
		c.Summary = "vulnerable build accepts stale key; localized fix rejects it"
	case kind == "attack" && vulnBug && fixed.VerdictLabel == "FRAME_ACCEPTED":
		c.Summary = "fix ineffective: stale key still accepted"
	case kind == "benign" && vuln.VerdictLabel == "FRAME_ACCEPTED" &&
		fixed.VerdictLabel == "FRAME_ACCEPTED":
		c.Summary = "benign frame accepted by both builds (no regression)"
	default:
		c.Summary = fmt.Sprintf("incomplete: vuln=%s fixed=%s",
			vuln.VerdictLabel, fixed.VerdictLabel)
	}
	return c
}

// WriteJSON writes the report as an indented JSON file and returns its path.
func WriteJSON(rep *SampleReport, dir, name string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+"_report.json")
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Bundle tars+gzips the JSON report plus all evidence files and the sample
// copy, giving each sample a standalone, hashable export artifact.
func Bundle(rep *SampleReport, reportPath, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	add := func(path, arcName string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = arcName
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	}

	if err := add(reportPath, filepath.Base(reportPath)); err != nil {
		return err
	}
	if err := add(rep.Sample.RawPath,
		filepath.Join("sample", filepath.Base(rep.Sample.RawPath))); err != nil {
		return err
	}
	for _, e := range rep.Evidence {
		phaseDir := filepath.Base(filepath.Dir(e.Path))
		arcName := phaseDir + "_" + filepath.Base(e.Path)
		if err := add(e.Path, filepath.Join("evidence", arcName)); err != nil {
			return err
		}
	}
	return nil
}

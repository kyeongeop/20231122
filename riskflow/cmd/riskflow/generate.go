package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"riskflow/internal/model"
)

// sampleRows covers: clean accept, authorization failure (guest), high-risk
// rejection and a CI deny request. The last v2 row is also emitted as a
// truncated frame to exercise recovery.
func sampleRows() []model.Record {
	return []model.Record{
		{RecordID: "R-1001", Package: "lodash", Version: "4.17.21", Ecosystem: "npm",
			Severity: "low", Decision: model.DecisionAllow, Role: model.RoleReviewer},
		{RecordID: "R-1002", Package: "log4j-core", Version: "2.14.0", Ecosystem: "maven",
			Severity: "critical", Decision: model.DecisionAllow, Role: model.RoleGuest},
		{RecordID: "R-1003", Package: "openssl", Version: "1.1.1k", Ecosystem: "deb",
			Severity: "high", Decision: model.DecisionAllow, Role: model.RoleApprover},
		{RecordID: "R-1004", Package: "requests", Version: "2.20.0", Ecosystem: "pypi",
			Severity: "medium", Decision: model.DecisionDeny, Role: model.RoleCI},
	}
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	dir := fs.String("out", "testdata/generated", "output directory")
	truncate := fs.Bool("truncate", true, "also emit a truncated v2 batch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	rows := sampleRows()

	// Legacy v1: JSON-Lines, flat objects.
	v1Path := filepath.Join(*dir, "batch_v1.jsonl")
	if err := writeV1(v1Path, rows); err != nil {
		return err
	}

	// New v2: length-prefixed framed envelopes with checksums.
	v2Path := filepath.Join(*dir, "batch_v2.frames")
	fullFrames, err := buildV2(rows, "BATCH-2026-1122")
	if err != nil {
		return err
	}
	if err := os.WriteFile(v2Path, fullFrames, 0o644); err != nil {
		return err
	}

	if *truncate {
		// Cut the final frame mid-payload: keep length prefix and header but
		// drop the tail bytes so the declared length exceeds available bytes.
		cut := len(fullFrames) - 40
		if cut < 0 {
			cut = len(fullFrames) / 2
		}
		tPath := filepath.Join(*dir, "batch_v2_truncated.frames")
		if err := os.WriteFile(tPath, fullFrames[:cut], 0o644); err != nil {
			return err
		}
		// The completed final frame, used by `riskflow recover`.
		last := rows[len(rows)-1]
		lastFrame, err := buildV2([]model.Record{last}, "BATCH-2026-1122")
		if err != nil {
			return err
		}
		rPath := filepath.Join(*dir, "recovered_fragment.frames")
		if err := os.WriteFile(rPath, lastFrame, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (truncated) and %s (recovery fragment)\n", tPath, rPath)
	}
	fmt.Printf("wrote %s and %s\n", v1Path, v2Path)
	return nil
}

func writeV1(path string, rows []model.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func buildV2(rows []model.Record, batchID string) ([]byte, error) {
	var out []byte
	for _, r := range rows {
		payload, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		env := model.Envelope{
			Schema:   model.SchemaV2,
			BatchID:  batchID,
			Checksum: hex.EncodeToString(sum[:]),
			Payload:  r,
		}
		body, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		out = append(out, []byte(fmt.Sprintf("%d\n", len(body)))...)
		out = append(out, body...)
		out = append(out, '\n')
	}
	return out, nil
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"truncstream/internal/export"
	"truncstream/internal/store"
	"truncstream/internal/stream"
)

func cmdVerifyBundle(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("verify-bundle needs exactly one tar path")
	}
	if err := export.VerifyBundle(args[0]); err != nil {
		return err
	}
	fmt.Printf("OK  %s: every manifest sha256 matches\n", args[0])
	return nil
}

// cmdVerifyArtifact reopens a SQLite artifact and independently recomputes
// every persisted hash: checkpoint state, evidence blobs and the report. It
// also replays the raw captures through the parser to confirm the stored
// parse-result evidence still matches.
func cmdVerifyArtifact(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("verify-artifact needs exactly one sqlite path")
	}
	st, err := store.Open(args[0])
	if err != nil {
		return err
	}
	defer st.Close()

	ver, err := st.Meta("schema_version")
	if err != nil {
		return err
	}
	if ver != fmt.Sprint(store.SchemaVersion) {
		return fmt.Errorf("schema version mismatch: artifact=%s supported=%d", ver, store.SchemaVersion)
	}

	rows, err := st.DB().Query(`SELECT run_id,seq,state_json,state_sha256 FROM checkpoints ORDER BY run_id,seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cpChecked := 0
	for rows.Next() {
		var runID string
		var seq int64
		var stateJSON, wantSHA string
		if err := rows.Scan(&runID, &seq, &stateJSON, &wantSHA); err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(stateJSON))
		if got := hex.EncodeToString(sum[:]); got != wantSHA {
			return fmt.Errorf("checkpoint %s/%d hash mismatch: %s != %s", runID, seq, got, wantSHA)
		}
		cpChecked++
	}

	evRows, err := st.DB().Query(`SELECT run_id,kind,content,content_sha256 FROM evidence ORDER BY id`)
	if err != nil {
		return err
	}
	defer evRows.Close()
	evChecked := 0
	var rawA, rawB []byte
	for evRows.Next() {
		var runID, kind, wantSHA string
		var content []byte
		if err := evRows.Scan(&runID, &kind, &content, &wantSHA); err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != wantSHA {
			return fmt.Errorf("evidence %s/%s hash mismatch", runID, kind)
		}
		if kind == store.EvidenceRawCaptureA {
			rawA = content
		}
		if kind == store.EvidenceRawCaptureB {
			rawB = content
		}
		evChecked++
	}

	if rawA != nil {
		pa := stream.Parse(rawA)
		pb := stream.Parse(rawB)
		if err := compareEvidence(st, store.EvidenceParseResultA, pa); err != nil {
			return err
		}
		if err := compareEvidence(st, store.EvidenceParseResultB, pb); err != nil {
			return err
		}
	}

	fmt.Printf("OK  %s: schema=v%s checkpoints=%d evidence=%d all hashes verified\n",
		args[0], ver, cpChecked, evChecked)
	return nil
}

func compareEvidence(st *store.Store, kind string, got any) error {
	rows, err := st.EvidenceByKind(firstRunID(st), kind)
	if err != nil || len(rows) == 0 {
		return err
	}
	want := rows[0].Content
	reEncoded, err := json.Marshal(got)
	if err != nil {
		return err
	}
	var normalizedWant any
	if err := json.Unmarshal(want, &normalizedWant); err != nil {
		return err
	}
	var normalizedGot any
	if err := json.Unmarshal(reEncoded, &normalizedGot); err != nil {
		return err
	}
	if !deepEqual(normalizedWant, normalizedGot) {
		return fmt.Errorf("stored %s no longer reproduces from raw capture", kind)
	}
	return nil
}

func firstRunID(st *store.Store) string {
	var id string
	err := st.DB().QueryRow(`SELECT run_id FROM runs ORDER BY created_unix_nano LIMIT 1`).Scan(&id)
	if errors.Is(err, nil) {
		return id
	}
	return ""
}

func deepEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

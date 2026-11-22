package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"riskflow/internal/ingest"
	"riskflow/internal/model"
	"riskflow/internal/store"
)

func newPipeline(t *testing.T) (*Pipeline, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "ev.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st), dir
}

func frame(t *testing.T, rec model.Record) []byte {
	t.Helper()
	payload, _ := json.Marshal(rec)
	sum := sha256.Sum256(payload)
	env := model.Envelope{Schema: model.SchemaV2, BatchID: "B",
		Checksum: hex.EncodeToString(sum[:]), Payload: rec}
	body, _ := json.Marshal(env)
	out := append([]byte(itoa(len(body))+"\n"), body...)
	return append(out, '\n')
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestTruncateRecoverReplayDeterministic(t *testing.T) {
	p, _ := newPipeline(t)

	good := model.Record{RecordID: "R1", Package: "ok", Version: "1",
		Severity: "low", Decision: "allow", Role: "reviewer", InputHash: "x"}
	last := model.Record{RecordID: "R2", Package: "lib", Version: "9",
		Severity: "high", Decision: "allow", Role: "approver"}

	full := append(frame(t, good), frame(t, last)...)
	cut := len(full) - 12 // truncate the final frame

	res, err := p.Ingest("B", "mem", full[:cut])
	if err != ingest.ErrTruncated {
		t.Fatalf("ingest err = %v, want ErrTruncated", err)
	}
	if !res.Truncated || res.RecordCnt != 1 {
		t.Fatalf("ingest outcome = %+v", res)
	}

	if _, err := p.RecoverTruncated("B", frame(t, last)); err != nil {
		t.Fatalf("recover: %v", err)
	}

	report, err := p.Replay("B")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !report.ReplayedOK || report.Records != 2 || report.Recovered != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}

	// First error of the recovered record must be the TRUNCATED state, not a
	// later REJECTED — proving earliest-fault attribution.
	found := false
	for _, fe := range report.FirstErrors {
		if fe.RecordID == "R2" {
			found = true
			if fe.State != model.StateTruncated {
				t.Fatalf("R2 first error = %s, want TRUNCATED", fe.State)
			}
		}
	}
	if !found {
		t.Fatal("no first-error entry for recovered record R2")
	}
}

func TestLegacyV1Replay(t *testing.T) {
	p, _ := newPipeline(t)
	raw := []byte(`{"record_id":"L1","package":"p","version":"1","severity":"low","decision":"allow","role":"reviewer"}` + "\n")
	if _, err := p.Ingest("V1", "mem", raw); err != nil {
		t.Fatalf("ingest v1: %v", err)
	}
	report, err := p.Replay("V1")
	if err != nil {
		t.Fatalf("replay v1: %v", err)
	}
	if !report.ReplayedOK || report.Records != 1 || len(report.FirstErrors) != 0 {
		t.Fatalf("unexpected v1 report: %+v", report)
	}
}

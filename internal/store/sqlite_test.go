package store

import (
	"testing"

	"github.com/example/syscallwhitelist/internal/model"
)

func TestSnapshotAndFindingRoundTrip(t *testing.T) {
	st, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	snap := model.Snapshot{
		Version: "v2", SourceID: "src", Signature: "sig",
		IssuedAt: "now", Fingerprint: "sha256:fp",
		Syscalls: []model.Syscall{{Number: 41, Name: "socket", Risk: "medium"}},
	}
	if err := st.SaveSnapshot(snap); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	got, ok, err := st.GetSnapshot("v2")
	if err != nil || !ok {
		t.Fatalf("get snapshot ok=%v err=%v", ok, err)
	}
	if len(got.Syscalls) != 1 || got.Syscalls[0].Name != "socket" {
		t.Fatalf("snapshot payload mismatch: %+v", got.Syscalls)
	}

	rec := model.Record{ID: "r1", Raw: "raw-bytes", Truncated: true}
	if err := st.SaveRawInput(rec, "sha256:deadbeef"); err != nil {
		t.Fatalf("save raw: %v", err)
	}

	finding := model.Finding{
		RecordID: "r1", Verdict: model.VerdictUndecidable,
		Reason: "truncated", SnapshotVersion: "v2",
		Evidence: map[string]string{"truncated": "true"},
		Steps:    []model.EvidenceStep{{Seq: 1, Stage: "ingest"}},
	}
	if err := st.SaveFinding(finding); err != nil {
		t.Fatalf("save finding: %v", err)
	}

	all, err := st.AllFindings()
	if err != nil || len(all) != 1 {
		t.Fatalf("all findings len=%d err=%v", len(all), err)
	}
	if all[0].Verdict != model.VerdictUndecidable ||
		all[0].Evidence["truncated"] != "true" ||
		len(all[0].Steps) != 1 {
		t.Fatalf("finding round trip mismatch: %+v", all[0])
	}

	versions, err := st.SnapshotVersions()
	if err != nil || len(versions) != 1 || versions[0] != "v2" {
		t.Fatalf("versions=%v err=%v", versions, err)
	}
}

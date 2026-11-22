package store

import (
	"path/filepath"
	"testing"

	"riskflow/internal/model"
)

func TestWALAndEvidencePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ev.db")

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := st.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal mode = %s, want wal", mode)
	}

	if err := st.UpsertBatch("B", model.SchemaV2, "uri", "sha", 10, true); err != nil {
		t.Fatal(err)
	}
	rec := model.Record{RecordID: "R1", Package: "p", Version: "1",
		Schema: model.SchemaV2, InputHash: "h", Raw: "{}"}
	if err := st.InsertRecord("B", rec); err != nil {
		t.Fatal(err)
	}
	tr := model.Transition{RecordID: "R1", Seq: 0, FromState: "",
		ToState: model.StateReceived, Actor: "reviewer", Permit: true,
		Granted: true, Reason: "ok", AttackInput: "p@1",
		TriggerSite: "ingest.gate", InputHash: "h"}
	if err := st.AppendTransition("B", tr); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFirstError("B", model.FirstError{
		RecordID: "R1", State: model.StateTruncated, Seq: 0,
		Reason: "x", InputHash: "h"}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Reopen: WAL + durable tables must make the evidence fully recoverable.
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	b, err := st2.Batch("B")
	if err != nil || !b.Truncated {
		t.Fatalf("batch not recovered: %+v err=%v", b, err)
	}
	recs, err := st2.RawRecords("B")
	if err != nil || len(recs) != 1 || recs[0].Raw != "{}" {
		t.Fatalf("records not recovered: %+v err=%v", recs, err)
	}
	trs, err := st2.Transitions("B", "R1")
	if err != nil || len(trs) != 1 || trs[0].ToState != model.StateReceived {
		t.Fatalf("transitions not recovered: %+v err=%v", trs, err)
	}
	firsts, err := st2.FirstErrors("B")
	if err != nil || len(firsts) != 1 || firsts[0].State != model.StateTruncated {
		t.Fatalf("first errors not recovered: %+v err=%v", firsts, err)
	}
}

func TestSameRecordIDAcrossBatchesIsIsolated(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "iso.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mk := func(batch, pkg string) {
		if err := st.UpsertBatch(batch, model.SchemaV2, "u", "s", 1, false); err != nil {
			t.Fatal(err)
		}
		rec := model.Record{RecordID: "DUP", Package: pkg, Version: "1",
			Schema: model.SchemaV2, InputHash: "h-" + batch, Raw: pkg}
		if err := st.InsertRecord(batch, rec); err != nil {
			t.Fatal(err)
		}
	}
	mk("B1", "pkg-one")
	mk("B2", "pkg-two")

	r1, err := st.RawRecords("B1")
	if err != nil || len(r1) != 1 || r1[0].Package != "pkg-one" {
		t.Fatalf("B1 isolation broken: %+v err=%v", r1, err)
	}
	r2, err := st.RawRecords("B2")
	if err != nil || len(r2) != 1 || r2[0].Package != "pkg-two" {
		t.Fatalf("B2 isolation broken: %+v err=%v", r2, err)
	}
}

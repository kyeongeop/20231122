package store

import (
	"path/filepath"
	"testing"
)

func TestCheckpointRoundTripPreservesOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.sqlite")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	row := RunRow{RunID: "r1", ObjectID: "obj", State: StateNew,
		InputSHA256: "abc", InputSize: 12}
	if err := st.CreateRun(row, 100, 200); err != nil {
		t.Fatal(err)
	}
	state := ProcessingState{
		RunID: "r1", NextSeq: 7, ConsumedFrames: 6,
		Accumulator:      map[string]int64{"dev101": 6030, "dev202": 12},
		SeenCheckpoints:  []int64{1, 4},
		InputFingerprint: "fp",
		Stage:            "PROCESSING",
	}
	hash1, err := st.SaveCheckpoint(Checkpoint{RunID: "r1", Seq: 4, FrameOffset: 88, FrameCRC32: 9}, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the artifact from disk and confirm byte-identical state.
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	cp, got, err := st2.LatestCheckpoint("r1")
	if err != nil {
		t.Fatal(err)
	}
	if cp.StateSHA256 != hash1 {
		t.Fatalf("state hash changed across reopen: %s != %s", cp.StateSHA256, hash1)
	}
	if got.NextSeq != 7 || got.ConsumedFrames != 6 ||
		got.Accumulator["dev101"] != 6030 || got.Stage != "PROCESSING" ||
		len(got.SeenCheckpoints) != 2 {
		t.Fatalf("reloaded state lost fields or order: %+v", got)
	}
}

func TestEvidenceHashAndDegradation(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "b.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateRun(RunRow{RunID: "r", ObjectID: "o", State: StateNew,
		InputSHA256: "x", InputSize: 1}, 10, 10); err != nil {
		t.Fatal(err)
	}
	digest, err := st.AddEvidence("r", EvidenceRawCaptureA, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.EvidenceByKind("r", EvidenceRawCaptureA)
	if err != nil || len(rows) != 1 || rows[0].SHA256 != digest {
		t.Fatalf("evidence round trip failed: %v", err)
	}
	if err := st.AddDegradation("r", 2, "reason", "detail"); err != nil {
		t.Fatal(err)
	}
	events, err := st.ListDegradation("r")
	if err != nil || len(events) != 1 || events[0].Reason != "reason" {
		t.Fatalf("degradation round trip failed: %v", err)
	}
	reportHash, err := st.SaveReport("r", `{"object_id":"o"}`)
	if err != nil {
		t.Fatal(err)
	}
	jsonText, gotHash, err := st.GetReport("r")
	if err != nil || gotHash != reportHash || jsonText != `{"object_id":"o"}` {
		t.Fatalf("report round trip failed: %v", err)
	}
}

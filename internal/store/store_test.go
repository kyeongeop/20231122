package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestJobLifecycle(t *testing.T) {
	s := openTemp(t)
	id, err := s.CreateJob("2026-11-22T00:00:00Z", `{"repeat":10}`, "abc", "running")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobStatus(id, "paused"); err != nil {
		t.Fatal(err)
	}
	j, err := s.GetJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != "paused" || j.MaterialSHA != "abc" {
		t.Fatalf("job=%+v", j)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateJob("t0", "{}", "h", "running")
	state := []byte{1, 2, 3, 4, 5}
	if err := s.SaveCheckpoint(Checkpoint{
		JobID: id, Seq: 1, SavedUTC: "t1", NextIndex: 42,
		HashState: state, Processed: 42, Degraded: 3,
	}); err != nil {
		t.Fatal(err)
	}
	cp, err := s.LatestCheckpoint(id)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil || cp.NextIndex != 42 || !bytes.Equal(cp.HashState, state) || cp.Degraded != 3 {
		t.Fatalf("cp=%+v", cp)
	}
	if err := s.SaveCheckpoint(Checkpoint{JobID: id, Seq: 2, SavedUTC: "t2", NextIndex: 99}); err != nil {
		t.Fatal(err)
	}
	cp, _ = s.LatestCheckpoint(id)
	if cp.NextIndex != 99 {
		t.Fatalf("latest=%+v", cp)
	}
	all, err := s.Checkpoints(id)
	if err != nil || len(all) != 2 {
		t.Fatalf("all=%v err=%v", all, err)
	}
}

func TestBatchesEventsMaterial(t *testing.T) {
	s := openTemp(t)
	id, _ := s.CreateJob("t0", "{}", "h", "running")
	if err := s.SaveBatch(Batch{JobID: id, StartIndex: 0, EndIndex: 9, OutSHA256: "x", OutBytes: 100, RawOffset: 4096, TsUTC: "t1"}); err != nil {
		t.Fatal(err)
	}
	bs, err := s.Batches(id)
	if err != nil || len(bs) != 1 || bs[0].RawOffset != 4096 {
		t.Fatalf("bs=%+v err=%v", bs, err)
	}
	if err := s.SaveEvent(Event{JobID: id, TsUTC: "t1", Kind: KindDegraded, RecordIndex: 7, RawOffset: 123, Detail: "d"}); err != nil {
		t.Fatal(err)
	}
	evs, err := s.Events(id)
	if err != nil || len(evs) != 1 || evs[0].RawOffset != 123 {
		t.Fatalf("evs=%+v err=%v", evs, err)
	}
	mat := []byte("original-material-bytes")
	if err := s.SaveMaterial(id, "sha", mat); err != nil {
		t.Fatal(err)
	}
	sha, got, err := s.LoadMaterial(id)
	if err != nil || sha != "sha" || !bytes.Equal(got, mat) {
		t.Fatalf("sha=%q got=%q err=%v", sha, got, err)
	}
}

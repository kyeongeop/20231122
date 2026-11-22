package runner

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tve/internal/material"
	"tve/internal/store"
)

func testParams() Params {
	return Params{
		Seed: 7, Repeat: 500, TemplatePad: 256, ValueLen: 300,
		BatchSize: 50, MaxValueBytes: 128, MaxOutputBytes: 8192,
	}
}

func setup(t *testing.T, p Params) (*store.Store, int64, []byte) {
	t.Helper()
	st, err := store.OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mat := material.Generate(p.Seed)
	pj, _ := json.Marshal(p)
	id, err := st.CreateJob("2026-11-22T00:00:00Z", string(pj), material.SHA256(mat), "running")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveMaterial(id, material.SHA256(mat), mat); err != nil {
		t.Fatal(err)
	}
	return st, id, mat
}

func TestPauseResumeEqualsUninterrupted(t *testing.T) {
	p := testParams()
	p.PauseAfter = 230
	st, id, mat := setup(t, p)

	r := NewRunner(st, id, p, mat)
	if err := r.Run(); !errors.Is(err, ErrPaused) {
		t.Fatalf("want ErrPaused, got %v", err)
	}
	r2, err := ResumeRunner(st, id, p, mat)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Run(); err != nil {
		t.Fatalf("resume run: %v", err)
	}

	want, _, err := Reference(p, mat)
	if err != nil {
		t.Fatal(err)
	}
	if r2.FinalHash() != want {
		t.Fatalf("resumed hash %s != reference %s", r2.FinalHash(), want)
	}
	job, _ := st.GetJob(id)
	if job.Status != "completed" {
		t.Fatalf("status=%s", job.Status)
	}
}

func TestResourceExhaustionDegradesAndResumes(t *testing.T) {
	p := testParams()
	p.OutputBudget = 150000 // trips partway through the run
	st, id, mat := setup(t, p)

	r := NewRunner(st, id, p, mat)
	if err := r.Run(); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("want ErrResourceExhausted, got %v", err)
	}
	r2, err := ResumeRunner(st, id, p, mat)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Degraded() {
		t.Fatal("expected degraded mode after exhaustion")
	}
	if err := r2.Run(); err != nil {
		t.Fatalf("degraded resume: %v", err)
	}
	want, _, err := Reference(p, mat)
	if err != nil {
		t.Fatal(err)
	}
	if r2.FinalHash() != want {
		t.Fatalf("degraded resumed hash %s != reference %s", r2.FinalHash(), want)
	}
	evs, _ := st.Events(id)
	var sawResource, sawDegraded bool
	for _, e := range evs {
		if e.Kind == store.KindResource {
			sawResource = true
		}
		if e.Kind == store.KindDegraded {
			sawDegraded = true
		}
	}
	if !sawResource || !sawDegraded {
		t.Fatalf("resource=%v degraded=%v", sawResource, sawDegraded)
	}
}

func TestVerifyAcceptance(t *testing.T) {
	p := testParams()
	p.PauseAfter = 30
	p.OutputBudget = 150000 // trips after the pause
	st, id, mat := setup(t, p)
	dir := t.TempDir()
	if _, err := material.Preserve(dir, mat); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }

	r := NewRunner(st, id, p, mat)
	r.Now = tick
	if err := r.Run(); !errors.Is(err, ErrPaused) {
		t.Fatalf("got %v", err)
	}
	r2, _ := ResumeRunner(st, id, p, mat)
	r2.Now = tick
	if err := r2.Run(); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("got %v", err)
	}
	r3, _ := ResumeRunner(st, id, p, mat)
	r3.Now = tick
	if err := r3.Run(); err != nil {
		t.Fatalf("final resume: %v", err)
	}

	rep, err := Verify(st, id, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range rep.Lines {
		t.Log(l)
	}
	if !rep.OK {
		t.Fatal("acceptance failed")
	}
}

func TestVerifyDetectsTamperedMaterial(t *testing.T) {
	p := testParams()
	st, id, mat := setup(t, p)
	r := NewRunner(st, id, p, mat)
	if err := r.Run(); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), mat...)
	tampered[0] ^= 0xff
	if err := st.SaveMaterial(id, material.SHA256(mat), tampered); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(st, id, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("tampered material must fail acceptance")
	}
}

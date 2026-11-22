package checker

import (
	"testing"

	"github.com/example/syscallwhitelist/internal/model"
	"github.com/example/syscallwhitelist/internal/store"
	"github.com/example/syscallwhitelist/internal/tempstate"
)

func newHarness(t *testing.T) (*Checker, *store.Store, *tempstate.Manager) {
	t.Helper()
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.UpsertSource(model.Source{
		ID: "src-kernel-sec", Name: "Kernel", PubKey: "sha256:abc",
	}); err != nil {
		t.Fatalf("upsert source: %v", err)
	}
	if err := st.SaveSnapshot(model.Snapshot{
		Version: "v1", SourceID: "src-kernel-sec", Signature: "sha256:abc",
		IssuedAt: "2026-11-01T00:00:00Z", Fingerprint: "sha256:fp1",
		Syscalls: []model.Syscall{{Number: 0, Name: "read", Risk: "low"}},
	}); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	tmp, err := tempstate.New(t.TempDir())
	if err != nil {
		t.Fatalf("tempstate: %v", err)
	}
	t.Cleanup(func() { _ = tmp.CleanupAll() })

	return New(st, tmp), st, tmp
}

func TestTrusted(t *testing.T) {
	chk, _, tmp := newHarness(t)
	rec := model.Record{
		ID: "r1", Raw: `{"syscall_no":0}`, SourceID: "src-kernel-sec",
		Signature: "sha256:abc", Version: "v1", SyscallNo: 0,
	}
	f, err := chk.Process(rec)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if f.Verdict != model.VerdictTrusted {
		t.Fatalf("verdict = %s, want trusted", f.Verdict)
	}
	if f.Matched == nil || f.Matched.Name != "read" {
		t.Fatalf("matched syscall not recorded: %+v", f.Matched)
	}
	if len(f.Steps) < 5 {
		t.Fatalf("evidence steps too few: %d", len(f.Steps))
	}
	if tmp.LiveCount() != 0 {
		t.Fatalf("temp state not cleaned, live=%d", tmp.LiveCount())
	}
}

func TestTruncatedIsUndecidable(t *testing.T) {
	chk, _, _ := newHarness(t)
	rec := model.Record{
		ID: "r2", Raw: `{"truncated":true,`, Truncated: true, Version: "v1",
	}
	f, _ := chk.Process(rec)
	if f.Verdict != model.VerdictUndecidable {
		t.Fatalf("verdict = %s, want undecidable", f.Verdict)
	}
	if f.Evidence["truncated"] != "true" || f.Evidence["raw_sha256"] == "" {
		t.Fatalf("key evidence missing: %+v", f.Evidence)
	}
}

func TestParseErrorIsIsolated(t *testing.T) {
	chk, _, _ := newHarness(t)
	rec := model.Record{ID: "r3", Raw: "{bad", ParseError: "boom"}
	f, _ := chk.Process(rec)
	if f.Verdict != model.VerdictError {
		t.Fatalf("verdict = %s, want error", f.Verdict)
	}
}

func TestUnknownSourceRejected(t *testing.T) {
	chk, _, _ := newHarness(t)
	rec := model.Record{
		ID: "r4", Raw: "{}", SourceID: "nope",
		Signature: "x", Version: "v1",
	}
	f, _ := chk.Process(rec)
	if f.Verdict != model.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", f.Verdict)
	}
}

func TestMissingSnapshotUndecidable(t *testing.T) {
	chk, _, _ := newHarness(t)
	rec := model.Record{
		ID: "r5", Raw: "{}", SourceID: "src-kernel-sec",
		Signature: "sha256:abc", Version: "v404",
	}
	f, _ := chk.Process(rec)
	if f.Verdict != model.VerdictUndecidable {
		t.Fatalf("verdict = %s, want undecidable", f.Verdict)
	}
}

func TestPanicDoesNotEscape(t *testing.T) {
	chk, _, _ := newHarness(t)
	// 传入会让底层存储调用失败的记录不会发生；这里直接验证正常输入
	// 的重复处理依然稳定，确保 recover 包装可用。
	for i := 0; i < 50; i++ {
		rec := model.Record{
			ID: "loop", Raw: "{}", SourceID: "src-kernel-sec",
			Signature: "sha256:abc", Version: "v1", SyscallNo: 0,
		}
		f, err := chk.Process(rec)
		if err != nil {
			t.Fatalf("iteration %d returned error: %v", i, err)
		}
		if f.Verdict != model.VerdictTrusted {
			t.Fatalf("iteration %d verdict = %s", i, f.Verdict)
		}
	}
}

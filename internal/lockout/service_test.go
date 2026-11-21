package lockout

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestParseEmptyInput(t *testing.T) {
	if _, err := ParseRequests(nil); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("want ErrEmptyInput, got %v", err)
	}
	if _, err := ParseRequests([]byte{}); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("want ErrEmptyInput for zero-len, got %v", err)
	}
}

func TestParseOversizedRecord(t *testing.T) {
	raw := []byte(Magic)
	raw = append(raw, 1, 0, 0, 0) // 1 条记录
	raw = append(raw, 0xFF, 0xFF, 0xFF, 0xFF)
	_, err := ParseRequests(raw)
	if !errors.Is(err, ErrOversized) {
		t.Fatalf("want ErrOversized, got %v", err)
	}
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Offset != 8 {
		t.Fatalf("want ParseError at offset 8, got %v", err)
	}
}

func TestRawOffsets(t *testing.T) {
	reqs := []Request{
		{RequestID: "r1", Username: "u", Password: "p", Timestamp: 1},
		{RequestID: "r2", Username: "u", Password: "p", Timestamp: 2},
	}
	raw := EncodeCapture(reqs)
	parsed, err := ParseRequests(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("want 2, got %d", len(parsed))
	}
	if parsed[0].RawOffset != 8 {
		t.Fatalf("first record offset = %d, want 8", parsed[0].RawOffset)
	}
	want := int64(8 + 4 + parsed[0].Length)
	if parsed[1].RawOffset != want {
		t.Fatalf("second record offset = %d, want %d", parsed[1].RawOffset, want)
	}
}

// TestDuplicateObjectAnomaly 复现核心异常: 5 次失败事件(含 1 个重复对象,
// 两个副本并发)因丢失更新只计 4 次, 锁定阈值 5 永远达不到, 锁定被绕过。
func TestDuplicateObjectAnomaly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := NewService(store)
	mk := func(id string) Request {
		return Request{RequestID: id, Username: "alice", Password: "x",
			Timestamp: time.Now().UnixNano()}
	}
	// 3 次唯一失败先顺序到达
	for _, id := range []string{"a", "b", "c"} {
		if err := svc.Handle(mk(id)); err != nil {
			t.Fatal(err)
		}
	}
	// 重复对象的两个副本并发到达
	if err := svc.ProcessConcurrent([]Request{mk("dup"), mk("dup")}); err != nil {
		t.Fatal(err)
	}
	failCount, lockedUntil, err := store.GetAccount("alice")
	if err != nil {
		t.Fatal(err)
	}
	if failCount != 4 {
		t.Fatalf("fail_count = %d, want 4 (5 次失败事件丢失 1 次更新)", failCount)
	}
	if lockedUntil != 0 {
		t.Fatalf("异常场景下锁定被绕过, locked_until 应为 0, got %d", lockedUntil)
	}
	// 攻击收益: 第 6 次请求仍被权限判断放行(本应已锁定)
	probe := mk("probe")
	if err := svc.Handle(probe); err != nil {
		t.Fatal(err)
	}
	rows, err := store.DumpAttempts()
	if err != nil {
		t.Fatal(err)
	}
	var dupIncrements int
	var sawProbeAllow bool
	for _, r := range rows {
		if r.RequestID == "dup" && r.Phase == "increment" {
			dupIncrements++
		}
		if r.RequestID == "probe" && r.Phase == "authorize" && r.Decision == "ALLOW" {
			sawProbeAllow = true
		}
	}
	if dupIncrements != 2 {
		t.Fatalf("重复对象应产生 2 条 increment 证据, got %d", dupIncrements)
	}
	if !sawProbeAllow {
		t.Fatal("缺少 probe 被 ALLOW 的证据行(锁定绕过的攻击收益)")
	}
}

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"lockrecon/internal/lockout"
)

const evidenceDir = "evidence"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "reconstruct failed:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return err
	}
	rawPath := filepath.Join(evidenceDir, "raw_capture.bin")
	dbPath := filepath.Join(evidenceDir, "lockout.db")
	// 重建幂等: 清除上一轮证据库
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(dbPath + suffix)
	}

	// 1. 构造原始材料: 3 次唯一失败 + 1 个重复对象(同一 RequestID 出现两次)
	//    + 锁定后的 1 次探测。逻辑失败仅 4 次, 低于阈值 5。
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	mk := func(id, user string, sec int) lockout.Request {
		return lockout.Request{RequestID: id, Username: user, Password: "bad-pass",
			Timestamp: base.Add(time.Duration(sec) * time.Second).UnixNano()}
	}
	dupID := "aa11bb22cc33dd44ee55ff6600112233"
	probe := mk("00000000000000000000000000000004", "alice", 4)
	probe.Success = true // 锁定后探测: 持合法凭据登录
	reqs := []lockout.Request{
		mk("00000000000000000000000000000001", "alice", 0),
		mk("00000000000000000000000000000002", "alice", 1),
		mk("00000000000000000000000000000003", "alice", 2),
		mk(dupID, "alice", 3), // 重复对象: 原始
		mk(dupID, "alice", 3), // 重复对象: 重放副本
		probe,                 // 锁定后探测: 若锁定生效应被拒绝
	}
	raw := lockout.EncodeCapture(reqs)
	sum := sha256.Sum256(raw)
	rawSHA := hex.EncodeToString(sum[:])
	os.Remove(rawPath)                                        // 上一轮原件为只读, 先移除再写入
	if err := os.WriteFile(rawPath, raw, 0o444); err != nil { // 只读: 保留未修改原件
		return err
	}
	if err := os.WriteFile(rawPath+".sha256", []byte(rawSHA+"  raw_capture.bin\n"), 0o644); err != nil {
		return err
	}

	store, err := lockout.OpenStore(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.LogEvidence("original_material", 0, rawSHA,
		fmt.Sprintf("raw_capture.bin bytes=%d mode=0444", len(raw))); err != nil {
		return err
	}

	// 2. 解析并记录每条请求的原始偏移
	parsed, err := lockout.ParseRequests(raw)
	if err != nil {
		return err
	}
	for _, r := range parsed {
		if _, err := store.LogAttempt(r.RequestID, r.RawOffset, r.Username,
			"parsed", "OK", fmt.Sprintf("len=%d ts=%d", r.Length, r.Timestamp)); err != nil {
			return err
		}
	}

	// 3. 重放: 3 次唯一失败顺序到达, 重复对象两副本并发到达, 最后是锁定后探测
	svc := lockout.NewService(store)
	for _, r := range parsed[:3] {
		if err := svc.Handle(r); err != nil {
			return err
		}
	}
	if err := svc.ProcessConcurrent(parsed[3:5]); err != nil {
		return err
	}
	if err := svc.Handle(parsed[5]); err != nil {
		return err
	}

	// 4. 空输入与超大输入处理, 证据入库
	if _, err := lockout.ParseRequests(nil); err != nil {
		if _, err := store.LogEvidence("empty_input", 0, "", err.Error()); err != nil {
			return err
		}
	}
	oversized := buildOversizedBlob()
	osum := sha256.Sum256(oversized)
	if _, perr := lockout.ParseRequests(oversized); perr != nil {
		if _, err := store.LogEvidence("oversized_input", 8, hex.EncodeToString(osum[:]),
			fmt.Sprintf("declared_len=%d err=%v", binary.LittleEndian.Uint32(oversized[8:12]), perr)); err != nil {
			return err
		}
	}

	// 5. 校验原件未被修改
	after, err := os.ReadFile(rawPath)
	if err != nil {
		return err
	}
	asum := sha256.Sum256(after)
	if hex.EncodeToString(asum[:]) != rawSHA {
		return fmt.Errorf("原始材料被修改: sha256 不匹配")
	}

	return writeReport(store, rawSHA, len(raw), dupID)
}

func buildOversizedBlob() []byte {
	var b []byte
	b = append(b, []byte(lockout.Magic)...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 1)
	b = append(b, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], lockout.MaxRecordSize+1) // 声明超长
	b = append(b, tmp[:]...)
	b = append(b, make([]byte, 64)...) // 实际只给少量字节
	return b
}

//go:build cgofuzz

// Package main 把 Go 侧的来源检查流水线接入 libFuzzer。
// 构建方式见 fuzz/build.sh：clang -fsanitize=fuzzer 链接导出的 Go 函数。
package main

/*
#include <stddef.h>
#include <stdint.h>

// 由 Go 通过 //export 提供（cgo 导出签名不带 const）。
extern void goFuzzerEntry(uint8_t* data, size_t size);

// libFuzzer 每轮调用的 C 入口，转发到 Go 实现。
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	goFuzzerEntry((uint8_t*)data, size);
	return 0;
}
*/
import "C"

import (
	"encoding/json"

	"github.com/example/syscallwhitelist/internal/checker"
	"github.com/example/syscallwhitelist/internal/model"
	"github.com/example/syscallwhitelist/internal/store"
	"github.com/example/syscallwhitelist/internal/tempstate"
)

// fuzzEnvelope 是 fuzz 输入的简化信封，字段均可选，刻意覆盖畸形输入。
type fuzzEnvelope struct {
	ID        string `json:"id"`
	SourceID  string `json:"source_id"`
	Signature string `json:"signature"`
	Version   string `json:"version"`
	SyscallNo int    `json:"syscall_no"`
	Truncated bool   `json:"truncated"`
}

//export goFuzzerEntry
func goFuzzerEntry(data *C.uint8_t, size C.size_t) {
	raw := cBytes(data, size)

	// 纯内存 SQLite，避免 fuzz 过程触碰宿主文件系统。
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		panic(err)
	}
	defer st.Close()

	must(st.UpsertSource(model.Source{
		ID:     "src-kernel-sec",
		Name:   "Kernel Security Team",
		PubKey: "sha256:abc",
	}))
	must(st.SaveSnapshot(model.Snapshot{
		Version:     "v1",
		SourceID:    "src-kernel-sec",
		Signature:   "sha256:abc",
		IssuedAt:    "2026-11-01T00:00:00Z",
		Fingerprint: "sha256:fixed",
		Syscalls: []model.Syscall{
			{Number: 0, Name: "read", Risk: "low"},
			{Number: 59, Name: "execve", Risk: "high"},
		},
	}))

	tmp, err := tempstate.New("/tmp")
	if err != nil {
		panic(err)
	}
	defer func() { _ = tmp.CleanupAll() }()

	rec := model.Record{ID: "fuzz", Raw: string(raw)}
	var env fuzzEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		rec.ParseError = err.Error()
	} else {
		rec.SourceID = env.SourceID
		rec.Signature = env.Signature
		rec.Version = env.Version
		rec.SyscallNo = env.SyscallNo
		rec.Truncated = env.Truncated
	}

	chk := checker.New(st, tmp)
	// 检查器内部已 recover panic；任何返回 error 结论之外的崩溃都会被
	// libFuzzer 捕获并落盘为 crash-* 用例。
	_, _ = chk.Process(rec)

	if tmp.LiveCount() != 0 {
		panic("temp state leaked after processing fuzz input")
	}
}

func main() {}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

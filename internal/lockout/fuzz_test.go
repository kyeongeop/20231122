package lockout

import (
	"errors"
	"testing"
)

// FuzzParseRequests 是 libFuzzer 风格的覆盖率引导 fuzz 目标
// (Go 原生 fuzzing 引擎, 与 libFuzzer 同源)。重点验证:
// 空输入、超大输入、截断输入均不 panic 且返回显式错误。
func FuzzParseRequests(f *testing.F) {
	f.Add([]byte{})      // 空输入
	f.Add([]byte(Magic)) // 截断头部
	f.Add(EncodeCapture([]Request{{RequestID: "x", Username: "u", Password: "p"}}))
	oversized := append([]byte(Magic), 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF)
	f.Add(oversized) // 超大声明长度
	f.Fuzz(func(t *testing.T, data []byte) {
		reqs, err := ParseRequests(data)
		if len(data) == 0 && !errors.Is(err, ErrEmptyInput) {
			t.Fatalf("空输入必须返回 ErrEmptyInput, got %v", err)
		}
		if err == nil {
			// 解析成功时, 偏移必须单调递增且在输入范围内
			prev := int64(-1)
			for _, r := range reqs {
				if r.RawOffset <= prev || r.RawOffset >= int64(len(data)) {
					t.Fatalf("非法原始偏移 %d (len=%d)", r.RawOffset, len(data))
				}
				prev = r.RawOffset
			}
		}
	})
}

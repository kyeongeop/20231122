package parser

import "testing"

// FuzzWSFrame 是 libFuzzer 覆盖率制导引擎(Go 原生 fuzzing)的入口。
// 不变量:修复版绝不 panic;一旦接受,帧边界必须自洽。
// 差分不变量:原始版 panic 的输入,修复版必须拒绝。
func FuzzWSFrame(f *testing.F) {
	for _, seed := range [][]byte{
		{0x81},                                  // A1: 基础头截断
		{0x81, 0x7f, 0xff},                      // A2: 64 位扩展长度截断
		{0x81, 0x7e, 0xff, 0xff, 'x'},           // A3: 声明负载越界
		{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'},   // 合法帧
		{0x82, 0x85, 1, 2, 3, 4, 'h', 'e', 'l', 'l', 'o'}, // 合法掩码帧
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fixed := Parse(data, "fixed")
		if fixed.Panic != nil {
			t.Fatalf("fixed parser panicked: %v", fixed.Panic)
		}
		if fixed.Err == nil {
			fr := fixed.Frame
			if fr.PayloadLen > MaxPayload {
				t.Fatalf("accepted payload %d exceeds MaxPayload", fr.PayloadLen)
			}
			if uint64(fr.HeaderLen)+fr.PayloadLen > uint64(len(data)) {
				t.Fatalf("frame bounds %d+%d exceed input %d",
					fr.HeaderLen, fr.PayloadLen, len(data))
			}
		}
		vuln := Parse(data, "vulnerable")
		if vuln.Panic != nil && fixed.Err == nil {
			t.Fatalf("vulnerable panicked (%v) but fixed accepted input", vuln.Panic)
		}
	})
}

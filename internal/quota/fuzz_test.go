package quota

import (
	"testing"

	"quotabypass/internal/evidence"
)

// FuzzParseAndReplay 是 libFuzzer 风格的覆盖率引导 fuzz 目标。
//
// 运行方式（Go 原生 fuzzing，引擎为 libFuzzer 移植版）：
//
//	go test -fuzz=FuzzParseAndReplay -fuzztime=30s ./internal/quota
//
// 语料：fuzz/corpus/FuzzParseAndReplay（含空输入与超大输入种子）。
func FuzzParseAndReplay(f *testing.F) {
	f.Add([]byte(RawBaseline))
	f.Add([]byte(RawAttackMissingFragment))
	f.Add([]byte(RawCapacityPressure))
	f.Add([]byte(""))
	f.Add(make([]byte, MaxInputBytes))
	f.Add([]byte("{broken json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		input, inputEv, parseErr := ParseInput(data)

		// 不变量 1：任何输入都必须产出输入证据，且哈希可复现。
		if inputEv.Bytes != len(data) {
			t.Fatalf("evidence bytes drift: %d != %d", inputEv.Bytes, len(data))
		}
		if inputEv.SHA256 == "" {
			t.Fatal("missing input hash evidence")
		}

		// 无效输入（空/超大/畸形）在解析阶段收敛，不进入判定。
		if parseErr != nil && !IsFragmentMissing(parseErr) {
			if input.ConcurrentRequests != 0 {
				t.Fatal("invalid input must not produce a parsed request count")
			}
			return
		}

		mode := ModeFixed
		if IsFragmentMissing(parseErr) {
			// 同一条畸形输入分别跑漏洞与修复两条路径。
			mode = ModeVulnerable
		}
		rec := NewRunner(mode).Run("fuzz", 0, data)
		if err := evidence.VerifyRecord(rec); err != nil {
			t.Fatalf("record verification: %v", err)
		}

		// 不变量 2：fixed 路径允许数不得超过配额（fail-closed 保证）。
		if mode == ModeFixed && rec.Summary.Allowed > input.QuotaCount {
			t.Fatalf("fixed path allowed %d > quota %d",
				rec.Summary.Allowed, input.QuotaCount)
		}

		// 不变量 3：确认绕用时必须保留缺失片段日志与触发位置证据。
		if rec.Summary.BypassDetected {
			if rec.Permission.Trigger.File != GateFile {
				t.Fatal("bypass without gate trigger evidence")
			}
			hasEvidence := false
			for _, l := range rec.Logs {
				if l.Event == "missing_fragments" {
					hasEvidence = true
				}
			}
			if !hasEvidence {
				t.Fatal("bypass without missing_fragments log evidence")
			}
		}

		// 不变量 4：同输入重放必须得到同一指纹（确定性）。
		again := NewRunner(mode).Run("fuzz", 0, data)
		if again.RecordSHA256 != rec.RecordSHA256 {
			t.Fatal("non-deterministic replay fingerprint")
		}
	})
}

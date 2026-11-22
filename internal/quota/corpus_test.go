package quota

import (
	"os"
	"path/filepath"
	"testing"

	"quotabypass/internal/evidence"
)

// TestCorpusSeeds 把 fuzz/corpus 下的每个种子作为 fuzz 目标输入执行一次，
// 保证人工维护的语料（含空输入、超大输入）始终通过全部不变量。
func TestCorpusSeeds(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "fuzz", "corpus", "FuzzParseAndReplay"))
	if err != nil {
		t.Skipf("corpus directory not found: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(
				"..", "..", "fuzz", "corpus", "FuzzParseAndReplay", name))
			if err != nil {
				t.Fatal(err)
			}
			input, inputEv, parseErr := ParseInput(data)
			if inputEv.SHA256 == "" {
				t.Fatal("missing hash evidence")
			}
			if parseErr != nil && !IsFragmentMissing(parseErr) {
				return
			}
			mode := ModeFixed
			if IsFragmentMissing(parseErr) {
				mode = ModeVulnerable
			}
			rec := NewRunner(mode).Run("corpus", 0, data)
			if err := evidence.VerifyRecord(rec); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if mode == ModeFixed && rec.Summary.Allowed > input.QuotaCount {
				t.Fatalf("fixed invariant violated: %d > %d",
					rec.Summary.Allowed, input.QuotaCount)
			}
		})
	}
}

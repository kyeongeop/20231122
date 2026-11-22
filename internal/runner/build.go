package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Toolchain struct {
	Clang    string
	CC       string
	Source   string
	BinDir   string
	FuzzBin  string
	PlainBin string
}

func Locate(repoRoot string) (*Toolchain, error) {
	clang := os.Getenv("CK_CLANG")
	if clang == "" {
		for _, cand := range []string{"clang", "clang-18", "clang-17", "clang-16"} {
			if p, err := exec.LookPath(cand); err == nil {
				clang = p
				break
			}
		}
	}
	if clang == "" {
		return nil, fmt.Errorf("clang not found; set CK_CLANG to a clang with libFuzzer")
	}
	cc := os.Getenv("CK_CC")
	if cc == "" {
		cc = "cc"
	}
	binDir := filepath.Join(repoRoot, "build")
	return &Toolchain{
		Clang: clang, CC: cc, BinDir: binDir,
		Source:   filepath.Join(repoRoot, "fuzz", "cookie_audit_fuzz.c"),
		FuzzBin:  filepath.Join(binDir, "cookie_audit_fuzz"),
		PlainBin: filepath.Join(binDir, "cookie_audit_plain"),
	}, nil
}

func (t *Toolchain) Build() error {
	if err := os.MkdirAll(t.BinDir, 0o755); err != nil {
		return err
	}
	if existing := os.Getenv("CK_SKIP_BUILD"); existing != "" {
		if _, err := os.Stat(t.FuzzBin); err == nil {
			if _, err := os.Stat(t.PlainBin); err == nil {
				return nil
			}
		}
	}
	sanitizers := "-fsanitize=address,undefined,fuzzer"
	fuzzCmd := exec.Command(t.Clang,
		"-g", "-O1", sanitizers, "-fno-omit-frame-pointer", "-DCK_NO_MAIN=1",
		"-o", t.FuzzBin, t.Source)
	fuzzCmd.Stdout = os.Stdout
	fuzzCmd.Stderr = os.Stderr
	if err := fuzzCmd.Run(); err != nil {
		return fmt.Errorf("build fuzz target: %w", err)
	}

	plainCmd := exec.Command(t.Clang,
		"-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
		"-o", t.PlainBin, t.Source)
	plainCmd.Stdout = os.Stdout
	plainCmd.Stderr = os.Stderr
	if err := plainCmd.Run(); err != nil {
		return fmt.Errorf("build plain rerun binary: %w", err)
	}
	return nil
}

func BuildFromWorkDir(workDir string) (*Toolchain, error) {
	tc, err := Locate(findRepoRoot())
	if err != nil {
		return nil, err
	}
	return tc, tc.Build()
}

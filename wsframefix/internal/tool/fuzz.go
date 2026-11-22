package tool

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wsframefix/internal/store"
)

// cmdFuzz 运行 Go 原生模糊测试引擎(基于 libFuzzer 的覆盖率制导实现),
// 把崩溃样本收割进 SQLite。语料缓存放在工作区内,Ctrl-C 中途退出后
// 重新执行同一命令即可从既有语料继续。
func cmdFuzz(args []string) error {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	dir := dirFlag(fs)
	seconds := fs.Int("seconds", 30, "模糊测试时长(秒)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cacheDir := filepath.Join(*dir, "gocache")
	crashDir := filepath.Join("internal", "parser", "testdata", "fuzz", "FuzzWSFrame")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, "go", "test",
		"-run=^$", "-fuzz=FuzzWSFrame",
		fmt.Sprintf("-fuzztime=%ds", *seconds), "./internal/parser")
	cmd.Env = append(os.Environ(), "GOCACHE="+abs(cacheDir))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fmt.Printf("libFuzzer 引擎启动,时长 %ds,语料缓存 %s(可 Ctrl-C 中断后重进)\n", *seconds, cacheDir)
	runErr := cmd.Run() // 崩溃样本会导致非零退出,属预期

	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := harvestCrashers(st, crashDir)
	if err != nil {
		return err
	}
	st.SetMeta("fuzz.last_run_at", time.Now().UTC().Format(time.RFC3339Nano))
	fmt.Printf("收割完成: 新增 %d 个攻击样本(中断/失败状态: %v)\n", n, runErr)
	return nil
}

// harvestCrashers 解析 testdata 语料文件并入库,按内容 sha256 去重。
func harvestCrashers(st *store.Store, crashDir string) (int, error) {
	entries, err := os.ReadDir(crashDir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	added := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(crashDir, e.Name()))
		if err != nil {
			return added, err
		}
		data, err := parseCorpusFile(string(raw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "跳过无法解析的语料 %s: %v\n", e.Name(), err)
			continue
		}
		_, fresh, err := st.AddSample("fuzz:"+e.Name(), sha256Hex(data), data)
		if err != nil {
			return added, err
		}
		if fresh {
			added++
		}
	}
	return added, nil
}

// parseCorpusFile 解析 `go test fuzz v1` 语料文件中的单个 []byte 值。
func parseCorpusFile(content string) ([]byte, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[]byte(") {
			q := strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")")
			s, err := strconv.Unquote(q)
			return []byte(s), err
		}
		if strings.HasPrefix(line, "string(") {
			q := strings.TrimSuffix(strings.TrimPrefix(line, "string("), ")")
			s, err := strconv.Unquote(q)
			return []byte(s), err
		}
	}
	return nil, fmt.Errorf("未找到 []byte/string 值")
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

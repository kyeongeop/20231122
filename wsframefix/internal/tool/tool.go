// Package tool 实现 wsframefix 命令行:围绕三个锚点(A1/A2/A3)对
// WebSocket 帧长度检查做局部修正,支持攻击样本的单独重跑、比较、
// 导出,以及中途退出后重新进入(全部状态落在 SQLite)。
package tool

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"wsframefix/internal/parser"
	"wsframefix/internal/store"
)

// Main 是 CLI 入口,返回进程退出码。
func Main(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit(args[1:])
	case "seed":
		err = cmdSeed(args[1:])
	case "fuzz":
		err = cmdFuzz(args[1:])
	case "run":
		err = cmdRun(args[1:])
	case "compare":
		err = cmdCompare(args[1:])
	case "export":
		err = cmdExport(args[1:])
	case "status":
		err = cmdStatus(args[1:])
	default:
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `wsframefix - WebSocket 帧长度检查局部修正工具

用法:
  wsframefix init   [-dir D]            初始化工作区,快照未修改的原始材料
  wsframefix seed   [-dir D]            生成三个锚点对应的基准攻击样本
  wsframefix fuzz   [-dir D] [-seconds N]  运行 libFuzzer 引擎并收割崩溃样本(可中断续跑)
  wsframefix run    [-dir D] -id N [-parser fixed|vulnerable|both]
  wsframefix compare [-dir D] -id N     原始版 vs 修复版逐锚点比较
  wsframefix export [-dir D] -id N [-out D]  导出证据包(原始字节+时间戳+偏移)
  wsframefix status [-dir D]            查看样本、锚点命中与最近运行时间
`)
}

func dirFlag(fs *flag.FlagSet) *string {
	return fs.String("dir", ".wsframefix", "工作区目录(含 evidence.db)")
}

func openStore(dir string) (*store.Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dir, "evidence.db"))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cmdInit 创建工作区,并把未修改的原始材料(解析器源码)快照到
// originals/,置为只读,清单与 sha256 写入 meta 表。
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := dirFlag(fs)
	src := fs.String("parser-src", "internal/parser/parser.go", "原始解析器源码路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	origDir := filepath.Join(*dir, "originals")
	if err := os.MkdirAll(origDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(origDir, "parser.go.orig")
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("原始材料已存在: %s(不会覆盖)", dst)
	}
	in, err := os.Open(*src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(out, io.TeeReader(in, h)); err != nil {
		out.Close()
		return err
	}
	out.Close()
	sum := hex.EncodeToString(h.Sum(nil))
	os.Chmod(dst, 0o444) // 保留一份未修改的原始材料

	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	st.SetMeta("original.parser.path", dst)
	st.SetMeta("original.parser.sha256", sum)
	st.SetMeta("original.snapshot_at", time.Now().UTC().Format(time.RFC3339Nano))
	fmt.Printf("原始材料已快照: %s\nsha256=%s\n", dst, sum)
	return nil
}

// seedAttacks 返回三个锚点各自的基准攻击样本。
func seedAttacks() map[string][]byte {
	a1 := []byte{0x81} // A1: 只有 1 字节,基础头被截断
	a2 := []byte{0x81, 0x7f, 0xff} // A2: 声明 64 位扩展长度但字段被截断
	a3 := []byte{0x81, 0x7e, 0xff, 0xff, 'x'} // A3: 声明 65535 字节负载,实际只有 1 字节
	return map[string][]byte{
		parser.AnchorHeader:  a1,
		parser.AnchorExtLen:  a2,
		parser.AnchorPayload: a3,
	}
}

func cmdSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	for anchor, data := range seedAttacks() {
		id, fresh, err := st.AddSample("seed:"+anchor, sha256Hex(data), data)
		if err != nil {
			return err
		}
		state := "已存在"
		if fresh {
			state = "新建"
		}
		fmt.Printf("样本 #%d [%s] %s (%d 字节, %s)\n", id, anchor, state, len(data), sha256Hex(data)[:12])
	}
	return nil
}

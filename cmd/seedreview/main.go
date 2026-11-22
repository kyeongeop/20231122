package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "seedreview:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr *os.File) error {
	if len(args) == 0 {
		printUsage(stderr)
		return fmt.Errorf("missing command")
	}
	switch args[0] {
	case "init":
		return runInit(ctx, args[1:], stdout)
	case "replay":
		return runReplay(ctx, args[1:], stdout)
	case "report":
		return runReport(ctx, args[1:], stdout)
	case "verify":
		return runVerify(ctx, args[1:], stdout)
	case "manual":
		return runManual(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(out *os.File) {
	fmt.Fprintln(out, `seedreview - 可复核的随机数种子审查

用法:
  seedreview init   --db <sqlite> --evidence <dir>
  seedreview replay --db <sqlite> --evidence <dir> --manifest <json>
                    [--target <binary>] [--artifact <file>] [--timeout 15s]
  seedreview report --db <sqlite> --evidence <dir> [--run <id>]
                    [--format markdown|json|legacy-json]
  seedreview manual --db <sqlite> --run <id> --check <code>
                    --status pending|confirmed|rejected [--owner <name>] [--notes <text>]
  seedreview verify --db <sqlite> --evidence <dir>

流程:
  恢复清单 -> libFuzzer 单次重放 -> trace/日志取证 -> SQLite 固化 -> 双栏报告`)
}

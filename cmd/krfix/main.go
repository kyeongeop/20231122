// krfix is the local "key-rotation failure" remediation controller. It keeps
// an immutable original material, replays each attack sample independently
// against vulnerable and fixed libFuzzer harnesses, persists every time point
// and raw offset in SQLite, supports stop/resume and exports per-sample
// evidence bundles.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"krfix/internal/material"
	"krfix/internal/store"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	workRoot, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	layout := material.NewLayout(workRoot)

	var err2 error
	switch cmd {
	case "-h", "--help", "help":
		usage()
	case "version":
		fmt.Println("krfix", version)
	case "init":
		err2 = runInit(layout, args)
	case "build":
		err2 = runBuild(layout, args)
	case "import":
		err2 = runImport(layout, args)
	case "fuzz":
		err2 = runFuzz(layout, args)
	case "run":
		err2 = runRun(layout, args)
	case "status":
		err2 = runStatus(layout, args)
	case "report":
		err2 = runReport(layout, args)
	case "export":
		err2 = runExport(layout, args)
	case "verify":
		err2 = runVerify(layout, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err2 != nil {
		fatal(err2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `krfix - key-rotation failure localized-fix controller

Usage:
  krfix init                 seal read-only original material + SQLite schema
  krfix build                compile libFuzzer vuln/fixed harnesses
  krfix import [--seed]      import deterministic corpus (or --file path)
  krfix fuzz [--phase vuln]  bounded libFuzzer campaign; keeps crashes
  krfix run [--sample N] [--phase vuln|fixed]
                             replay samples; resumable, Ctrl-C safe
  krfix status               show jobs, verdicts, time points and offsets
  krfix report --sample N    print per-sample JSON report
  krfix export --sample N    write report + evidence .tar.gz bundle
  krfix verify               re-hash the immutable original material
  krfix version
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "krfix:", err)
	os.Exit(1)
}

// openDB opens SQLite and recovers jobs interrupted by a previous process.
func openDB(layout material.Layout) (*sql.DB, context.Context, context.CancelFunc, error) {
	if err := os.MkdirAll(layout.Root, 0o755); err != nil {
		return nil, nil, nil, err
	}
	db, err := store.Open(layout.DBPath)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	n, err := store.ResetRunningOnStartup(ctx, db)
	if err != nil {
		cancel()
		db.Close()
		return nil, nil, nil, err
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "krfix: recovered %d interrupted job(s) from previous session\n", n)
	}
	return db, ctx, cancel, nil
}

func requireInit(layout material.Layout) {
	if _, err := os.Stat(layout.DBPath); err != nil {
		fatal(fmt.Errorf("workspace not initialized; run 'krfix init' first"))
	}
}

func resolveClang() string {
	if v := os.Getenv("CLANG"); v != "" {
		return v
	}
	if _, err := os.Stat("/tmp/toolchain/usr/bin/clang"); err == nil {
		return "/tmp/toolchain/usr/bin/clang"
	}
	return "clang"
}

func projectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd, nil
		}
		dir = parent
	}
}

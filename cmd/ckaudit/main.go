package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const usage = `ckaudit - Cookie attribute audit & local fuzzing correction tool

Usage:
  ckaudit init   [--work DIR] [--name N] [--runs N] [--max-len N] [--seed N]
  ckaudit run    [--work DIR] [--run ID]
  ckaudit resume [--work DIR]
  ckaudit fuzz   [--work DIR] [--run ID] [--runs N] [--max-len N] [--seed N] [--jobs N]
  ckaudit rerun  [--work DIR] --sample KEY [--run ID]
  ckaudit list   [--work DIR]
  ckaudit show   [--work DIR] --sample KEY [--run ID]
  ckaudit boundary [--work DIR] [--run ID]
  ckaudit compare [--work DIR] --a KEY --b KEY [--run ID]
  ckaudit export  [--work DIR] [--run ID] --out FILE [--format json|csv] [--evidence DIR]
  ckaudit stop    [--work DIR]
  ckaudit build   [--work DIR]

Environment:
  CK_CLANG   path to clang with libFuzzer runtime
  CK_CC      C compiler for the plain rerun binary (default: cc)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	workDir := flagValue(args, "--work", "ckaudit-work")
	workDir, _ = filepath.Abs(workDir)

	ctx := context.Background()
	var err error
	switch cmd {
	case "init":
		err = cmdInit(ctx, workDir, args)
	case "run":
		err = cmdRun(ctx, workDir, args)
	case "resume":
		err = cmdResume(ctx, workDir)
	case "fuzz":
		err = cmdFuzz(ctx, workDir, args)
	case "rerun":
		err = cmdRerun(ctx, workDir, args)
	case "list":
		err = cmdList(workDir)
	case "show":
		err = cmdShow(workDir, args)
	case "boundary":
		err = cmdBoundary(workDir, args)
	case "compare":
		err = cmdCompare(workDir, args)
	case "export":
		err = cmdExport(workDir, args)
	case "stop":
		err = cmdStop(workDir)
	case "build":
		err = cmdBuild(workDir)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ckaudit %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func flagValue(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if len(a) > len(name)+1 && a[:len(name)+1] == name+"=" {
			return a[len(name)+1:]
		}
	}
	return def
}

func flagInt(args []string, name string, def int64) int64 {
	v := flagValue(args, name, "")
	if v == "" {
		return def
	}
	var out int64
	if _, err := fmt.Sscanf(v, "%d", &out); err != nil {
		return def
	}
	return out
}

func repoRoot() string {
	if v := os.Getenv("CK_REPO_ROOT"); v != "" {
		return v
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

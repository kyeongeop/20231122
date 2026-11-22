package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"apiskew.local/apiskew/internal/bundle"
	"apiskew.local/apiskew/internal/store"
)

type cli struct {
	dbPath string
	stdout io.Writer
	stderr io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	dbPath, remaining, err := extractDBPath(args)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if len(remaining) == 0 {
		printUsage(stdout)
		return 0
	}
	c := &cli{dbPath: dbPath, stdout: stdout, stderr: stderr}
	command, commandArgs := remaining[0], remaining[1:]
	var commandErr error
	switch command {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "apiskew %s bundle %s\n", bundle.ToolVersion, bundle.Schema)
		return 0
	case "init":
		commandErr = c.init(ctx, commandArgs)
	case "list":
		commandErr = c.list(ctx, commandArgs)
	case "status":
		commandErr = c.status(ctx, commandArgs)
	case "pause":
		commandErr = c.setStatus(ctx, commandArgs, "paused")
	case "resume":
		commandErr = c.setStatus(ctx, commandArgs, "active")
	case "finish":
		commandErr = c.setStatus(ctx, commandArgs, "complete")
	case "discover":
		commandErr = c.discover(ctx, commandArgs)
	case "replay":
		commandErr = c.replay(ctx, commandArgs)
	case "compare":
		commandErr = c.compare(ctx, commandArgs)
	case "fix":
		commandErr = c.fix(ctx, commandArgs)
	case "export":
		commandErr = c.exportBundle(ctx, commandArgs)
	case "verify-bundle":
		commandErr = c.verifyBundle(commandArgs)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", command)
		printUsage(stderr)
		return 2
	}
	if commandErr == nil {
		return 0
	}
	if errors.Is(commandErr, context.Canceled) {
		fmt.Fprintln(stderr, "interrupted; evidence and checkpoint were preserved")
		return 130
	}
	if errors.Is(commandErr, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(stderr, "error:", commandErr)
	return 1
}

func extractDBPath(args []string) (string, []string, error) {
	dbPath := os.Getenv("APISKEW_DB")
	if dbPath == "" {
		dbPath = "apiskew.db"
	}
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--db":
			if i+1 >= len(args) {
				return "", nil, errors.New("--db requires a path")
			}
			dbPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--db="):
			dbPath = strings.TrimPrefix(arg, "--db=")
			if dbPath == "" {
				return "", nil, errors.New("--db requires a path")
			}
		default:
			remaining = append(remaining, arg)
		}
	}
	return dbPath, remaining, nil
}

func (c *cli) openStore() (*store.Store, error) {
	return store.Open(c.dbPath)
}

func (c *cli) sessionID(ctx context.Context, st *store.Store, id string) (string, error) {
	if id != "" {
		return id, nil
	}
	session, err := st.LatestSession(ctx)
	if err != nil {
		return "", err
	}
	return session.ID, nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func emitJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `apiskew %s - API version permission difference local correction tool

Usage:
  apiskew [--db PATH] <command> [flags]

Commands:
  init       Create a session for one duplicate object
  list       List sessions
  status     Show session progress, counts, and ordered samples
  discover   Run libFuzzer, import differential findings, and checkpoint
  replay     Re-run one or all samples with Go and optionally libFuzzer
  compare    Compare first/latest replay attempts for drift
  fix        Produce and verify a local v1 resolver correction plan
  pause      Mark a session paused
  resume     Mark a session active
  finish     Mark a session complete
  export     Write a self-contained review bundle
  verify-bundle  Re-evaluate an exported bundle without the source database

Global flag:
  --db PATH  SQLite database (default: $APISKEW_DB or apiskew.db)

Exit codes:
  0 success, 1 error, 2 usage, 130 interrupted
`, bundle.ToolVersion)
}

// Command tlsreg runs the replayable "TLS configuration regression"
// experiment: two frozen parser snapshots are exercised against a corpus
// (including a truncated control record), every step is journaled into
// SQLite, order-permutation and duplicate-submission checks are verified,
// and temporary state is cleaned up at the end.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "ingest-fuzz":
		err = cmdIngestFuzz(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  tlsreg run         --db <path> --artifacts <dir> [--seed N]
  tlsreg replay      --db <path> --run <run_id>
  tlsreg ingest-fuzz --db <path> --run <run_id> --dir <fuzz corpus dir>
  tlsreg report      --db <path> --run <run_id> --out <report.md>`)
}

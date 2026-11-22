// Command truncstream drives the pausable truncated-stream pipeline.
//
// Subcommands:
//
//	demo            end to end run: baseline vs suspended/resumed, compare, export
//	verify-bundle   independently verify a review bundle's hashes
//	verify-artifact reopen a SQLite artifact and recheck every stored hash
//	corpus          write fuzz seed corpus files
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
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "verify-bundle":
		err = cmdVerifyBundle(os.Args[2:])
	case "verify-artifact":
		err = cmdVerifyArtifact(os.Args[2:])
	case "corpus":
		err = cmdCorpus(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `truncstream - pausable truncated-stream processor

usage:
  truncstream demo [-dir DIR] [-frames N] [-truncate] [-suspend-after N]
  truncstream verify-bundle FILE.tar
  truncstream verify-artifact FILE.sqlite
  truncstream corpus DIR
`)
}

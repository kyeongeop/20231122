package main

import (
	"fmt"
	"os"
)

const usage = `taintlab - integer truncation taint evidence lab

Commands:
  run           Execute one input and store it in SQLite
  show          Reload one stored result without reordering fields
  verify-db     Verify every stored result and detail-row order
  export        Export a portable, self-verifying evidence package
  verify-export Verify an exported package and replay complete inputs
  demo          Build the two-device sample and edge-case artifacts
  help          Show this help
  version       Show the tool version
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "taintlab:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "show":
		return showCommand(args[1:])
	case "verify-db":
		return verifyDBCommand(args[1:])
	case "export":
		return exportCommand(args[1:])
	case "verify-export":
		return verifyExportCommand(args[1:])
	case "demo":
		return demoCommand(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "version":
		fmt.Println(toolVersion)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run taintlab help", args[0])
	}
}

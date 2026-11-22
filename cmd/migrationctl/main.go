package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 1
	}
	switch args[0] {
	case "review":
		return cmdReview(args[1:])
	case "demo":
		return cmdDemo(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "inspect":
		return cmdInspect(args[1:])
	case "fuzz-eval":
		return cmdFuzzEval(args[1:])
	case "version":
		return cmdVersion(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 1
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `migrationctl - reviewable SQLite migration permissions

Commands:
  review     Parse, authorize, execute (or deny) one migration and retain evidence
  demo       Run v2 allow, legacy attack deny, and mid-flight cancellation scenarios
  report     Render automatic conclusions and manual confirmation from evidence
  verify     Verify every log hash chain and artifact hash
  inspect    Print one run as JSON, including logs and evidence metadata
  fuzz-eval  Parse and authorize one fuzz input, useful for corpus regression
  version    Print Go and SQLite implementation details

Run "migrationctl <command> -h" for command flags.
`)
}

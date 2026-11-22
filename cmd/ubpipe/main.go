// ubpipe drives the pausable unicode-bypass processing flow.
//
// Usage:
//
//	ubpipe run    --db artifacts/evidence.db [--pause-after N] [--degrade-len N]
//	ubpipe resume --db artifacts/evidence.db
//	ubpipe report --db artifacts/evidence.db [--out artifacts/evidence_report.md]
package main

import (
	"flag"
	"fmt"
	"os"

	"unicodebypass/internal/pipeline"
	"unicodebypass/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(false, os.Args[2:])
	case "resume":
		err = cmdRun(true, os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: ubpipe run|resume|report --db PATH [flags]")
}

func cmdRun(resume bool, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dbPath := fs.String("db", "artifacts/evidence.db", "sqlite evidence db")
	pauseAfter := fs.Int("pause-after", 0, "pause after N items (0 = run to completion)")
	degradeLen := fs.Int("degrade-len", 4096, "names >= this many bytes use the degraded path")
	boundary := fs.Int("boundary", 255, "filename length boundary to sample")
	fs.Parse(args)

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	cfg := pipeline.DefaultConfig()
	cfg.PauseAfter = *pauseAfter
	cfg.DegradeLen = *degradeLen
	cfg.Boundary = *boundary

	items := pipeline.Generate()
	p, msg, err := pipeline.NewProcessor(db, cfg, items, resume)
	if err != nil {
		return err
	}
	fmt.Printf("run=%d segment=%s: %s (corpus=%d items)\n", p.RunID, p.Segment, msg, len(items))

	res, err := p.Process()
	if err != nil {
		return err
	}
	fmt.Printf("processed=%d findings=%d bypasses=%d degraded=%v paused=%v done=%v\n",
		res.Processed, res.Findings, res.Bypasses, res.Degraded, res.Paused, res.Done)
	if res.Paused {
		fmt.Println("checkpoint saved; continue with: ubpipe resume --db", *dbPath)
	}
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := fs.String("db", "artifacts/evidence.db", "sqlite evidence db")
	out := fs.String("out", "", "write report to file (default: stdout)")
	fs.Parse(args)

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rep, err := pipeline.Report(db)
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Print(rep)
		return nil
	}
	return os.WriteFile(*out, []byte(rep), 0o644)
}

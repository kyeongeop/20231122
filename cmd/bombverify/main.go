// Command bombverify reproduces the compression-bomb resource-exhaustion
// verification flow: it runs attack inputs through the quota-limited
// decompressor, records evidence in SQLite, and exports/reloads the
// evidence with a fixed field order for independent review.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bombverify/internal/decomp"
	"bombverify/internal/evidence"
	"bombverify/internal/runner"
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
	case "scenario":
		err = cmdScenario(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "reload":
		err = cmdReload(os.Args[2:])
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
  bombverify run      --input FILE [--scenario NAME] [--db DB] [--log LOG] [--subject ID] [--deny]
  bombverify scenario NAME|all [--db DB] [--log LOG] [--save-dir DIR] [--subject ID] [--deny]
  bombverify export   --db DB --out FILE
  bombverify reload   --in FILE --db DB [--source-db DB]`)
}

func openRun(dbPath, logPath string) (*evidence.Store, *runner.AuditLog, error) {
	st, err := evidence.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	au, err := runner.OpenAudit(logPath)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, au, nil
}

func subjectOf(id string, deny bool) runner.Subject {
	s := runner.Subject{ID: id}
	if !deny {
		s.Permissions = []string{runner.ActionDecompress}
	}
	return s
}

func printRecord(r *evidence.Record) {
	fmt.Printf("record_id=%s scenario=%s decision=%s trigger=%s:%d expanded=%d expansions=%d log_digest=%s\n",
		r.RecordID, r.Scenario, r.PermDecision, r.TriggerFile, r.TriggerLine,
		r.ExpandedBytes, r.ExpansionCount, r.LogDigest[:16])
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	input := fs.String("input", "", "attack input file")
	scenario := fs.String("scenario", "manual", "scenario label")
	db := fs.String("db", "artifacts/evidence.db", "evidence database")
	log := fs.String("log", "artifacts/audit.log", "audit log file")
	subject := fs.String("subject", "verifier", "subject id")
	deny := fs.Bool("deny", false, "withhold decompress permission")
	notes := fs.String("notes", "", "free-form notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	st, au, err := openRun(*db, *log)
	if err != nil {
		return err
	}
	defer st.Close()
	defer au.Close()
	rec, err := runner.Run(runner.Request{
		Scenario:     *scenario,
		AttackVector: "external file " + *input,
		Input:        data,
		Subject:      subjectOf(*subject, *deny),
		Quota:        decomp.DefaultQuota(),
		Notes:        *notes,
	}, st, au)
	if err != nil {
		return err
	}
	printRecord(rec)
	return nil
}

func cmdScenario(args []string) error {
	fs := flag.NewFlagSet("scenario", flag.ContinueOnError)
	db := fs.String("db", "artifacts/evidence.db", "evidence database")
	log := fs.String("log", "artifacts/audit.log", "audit log file")
	saveDir := fs.String("save-dir", "artifacts/inputs", "where to save generated inputs")
	subject := fs.String("subject", "verifier", "subject id")
	deny := fs.Bool("deny", false, "withhold decompress permission")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scenario name or 'all' required")
	}
	names := []string{fs.Arg(0)}
	if names[0] == "all" {
		names = runner.Scenarios()
	}
	q := decomp.DefaultQuota()
	st, au, err := openRun(*db, *log)
	if err != nil {
		return err
	}
	defer st.Close()
	defer au.Close()
	for _, name := range names {
		data, err := runner.BuildInput(name, q)
		if err != nil {
			return err
		}
		if *saveDir != "" {
			if err := os.MkdirAll(*saveDir, 0o755); err != nil {
				return err
			}
			p := filepath.Join(*saveDir, name+".bmb1")
			if err := os.WriteFile(p, data, 0o644); err != nil {
				return err
			}
		}
		rec, err := runner.Run(runner.Request{
			Scenario:     name,
			AttackVector: runner.AttackVector[name],
			Input:        data,
			Subject:      subjectOf(*subject, *deny),
			Quota:        q,
		}, st, au)
		if err != nil {
			return err
		}
		printRecord(rec)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	db := fs.String("db", "artifacts/evidence.db", "evidence database")
	out := fs.String("out", "artifacts/evidence.jsonl", "export file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := evidence.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := st.ExportJSONL(f)
	if err != nil {
		return err
	}
	fmt.Printf("exported %d records to %s (field order: %v)\n", n, *out, evidence.FieldOrder)
	return nil
}

func cmdReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	in := fs.String("in", "artifacts/evidence.jsonl", "exported JSONL")
	db := fs.String("db", "artifacts/reload.db", "target database")
	src := fs.String("source-db", "", "original database to verify against")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := evidence.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := st.ImportJSONL(f)
	if err != nil {
		return err
	}
	fmt.Printf("reloaded %d records into %s with fields and order preserved\n", n, *db)
	if *src != "" {
		orig, err := evidence.Open(*src)
		if err != nil {
			return err
		}
		defer orig.Close()
		m, err := orig.VerifyReload(st)
		if err != nil {
			return err
		}
		fmt.Printf("verified %d records against %s: identical\n", m, *src)
	}
	return nil
}

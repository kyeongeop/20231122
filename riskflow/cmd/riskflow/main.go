// Command riskflow drives the auditable dependency-risk review pipeline.
//
// Subcommands:
//
//	generate  emit v1/v2 sample batches (incl. a truncated record)
//	ingest    parse + persist a batch, recording truncation as evidence
//	recover   complete a truncated record and mark the batch recovered
//	replay    re-drive the state machine from SQLite evidence and diff trails
//	evidence  print the attack-input / trigger / permission / log mapping
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"riskflow/internal/replay"
	"riskflow/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "generate":
		err = cmdGenerate(args)
	case "ingest":
		err = cmdIngest(args)
	case "recover":
		err = cmdRecover(args)
	case "replay":
		err = cmdReplay(args)
	case "evidence":
		err = cmdEvidence(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "riskflow %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: riskflow <generate|ingest|recover|replay|evidence> [flags]")
}

func openStore(path string) (*store.Store, func(), error) {
	st, err := store.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return st, func() { _ = st.Close() }, nil
}

func cmdIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	db := fs.String("db", "riskflow.db", "evidence SQLite path")
	batch := fs.String("batch", "", "batch id (required)")
	file := fs.String("file", "", "input batch file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *batch == "" || *file == "" {
		return fmt.Errorf("--batch and --file are required")
	}
	st, closeFn, err := openStore(*db)
	if err != nil {
		return err
	}
	defer closeFn()
	p := replay.New(st)
	res, err := p.IngestFile(*batch, *file)
	fmt.Printf("ingest batch=%s schema=%s records=%d truncated=%v sha256=%s\n",
		res.BatchID, res.Schema, res.RecordCnt, res.Truncated, res.RawSHA256)
	if res.Truncated {
		fmt.Printf("truncation evidence: %s\n", res.Detail)
	}
	// A truncated batch is an expected, recoverable outcome, not a hard error.
	return nil
}

func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	db := fs.String("db", "riskflow.db", "evidence SQLite path")
	batch := fs.String("batch", "", "batch id (required)")
	file := fs.String("file", "", "completed fragment file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *batch == "" || *file == "" {
		return fmt.Errorf("--batch and --file are required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	st, closeFn, err := openStore(*db)
	if err != nil {
		return err
	}
	defer closeFn()
	p := replay.New(st)
	rec, err := p.RecoverTruncated(*batch, raw)
	if err != nil {
		return err
	}
	fmt.Printf("recovered record=%s package=%s@%s role=%s hash=%s\n",
		rec.RecordID, rec.Package, rec.Version, rec.Role, rec.InputHash)
	return nil
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	db := fs.String("db", "riskflow.db", "evidence SQLite path")
	batch := fs.String("batch", "", "batch id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *batch == "" {
		return fmt.Errorf("--batch is required")
	}
	st, closeFn, err := openStore(*db)
	if err != nil {
		return err
	}
	defer closeFn()
	p := replay.New(st)
	report, err := p.Replay(*batch)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func cmdEvidence(args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	db := fs.String("db", "riskflow.db", "evidence SQLite path")
	batch := fs.String("batch", "", "batch id (required)")
	record := fs.String("record", "", "record id (optional; default all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *batch == "" {
		return fmt.Errorf("--batch is required")
	}
	st, closeFn, err := openStore(*db)
	if err != nil {
		return err
	}
	defer closeFn()
	ids := []string{*record}
	if *record == "" {
		recs, err := st.RawRecords(*batch)
		if err != nil {
			return err
		}
		ids = ids[:0]
		for _, r := range recs {
			ids = append(ids, r.RecordID)
		}
	}
	for _, id := range ids {
		trs, err := st.Transitions(*batch, id)
		if err != nil {
			return err
		}
		fmt.Printf("record %s (%d evidence steps)\n", id, len(trs))
		for _, t := range trs {
			fmt.Printf("  seq=%d %-18s -> %-18s site=%-13s permit=%-5v granted=%-5v input=%q hash=%s\n    log: %s\n",
				t.Seq, t.FromState, t.ToState, t.TriggerSite, t.Permit, t.Granted,
				t.AttackInput, short(t.InputHash), t.Reason)
		}
		firsts, _ := st.FirstErrors(*batch)
		for _, fe := range firsts {
			if fe.RecordID == id {
				fmt.Printf("  FIRST ERROR STATE: %s at seq=%d (%s)\n",
					fe.State, fe.Seq, fe.Reason)
			}
		}
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

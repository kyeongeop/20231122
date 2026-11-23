// trustaudit is the reviewable pipeline for the reverse-proxy trust
// boundary: seed an audit log (old v1 + new v2 formats, plus one
// truncated record), recover from the truncation, then replay the
// salvaged records and pinpoint the first divergent state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"trustaudit/internal/record"
	"trustaudit/internal/replay"
	"trustaudit/internal/store"
	"trustaudit/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "seed":
		err = cmdSeed(os.Args[2:])
	case "recover":
		err = cmdRecover(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "all":
		err = cmdAll(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, `usage: trustaudit <command> [flags]
  seed     -db PATH            create audit log with v1/v2 records + truncated tail
  recover  -db PATH            quarantine truncated record, salvage valid rows
  replay   -db PATH -out FILE  replay salvaged records, write correlation report
  all      -db PATH -out FILE  seed (if fresh) + recover + replay`)
}

func dbFlag(args []string, needOut bool) (string, string, error) {
	fs := flag.NewFlagSet("cmd", flag.ContinueOnError)
	db := fs.String("db", "artifacts/audit.db", "sqlite database path")
	out := fs.String("out", "artifacts/report.json", "report output path")
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}
	return *db, *out, nil
}

// scenario returns the audit records to seed, in order. It mixes both
// record formats and ends with a truncated tail record, simulating a
// crash mid-write. Record 3 deliberately logs a wrong action so the
// replay has a real first-error state to find.
func scenario() [][]byte {
	const ts = 1763850000
	v1ok := record.EncodeV1(record.Record{
		TS: ts, Remote: "10.1.2.10", XFF: "203.0.113.50", Action: "allow"})
	v1direct := record.EncodeV1(record.Record{
		TS: ts + 1, Remote: "198.51.100.7", Action: "allow"})
	attackLogged := record.EncodeV2(record.Record{
		TS: ts + 2, Remote: "203.0.113.9", XFF: "10.0.0.5",
		Action: "allow", Rule: "R1-trusted-proxy",
		Reason: "logged by buggy proxy build"})
	blocked := record.EncodeV2(record.Record{
		TS: ts + 3, Remote: "10.1.2.10", XFF: "10.2.3.4",
		Action: "deny", Rule: "R5-blocked-client",
		Reason: "resolved client is on the blocklist"})
	truncated := record.EncodeV2(record.Record{
		TS: ts + 4, Remote: "10.1.2.10", XFF: "8.8.8.8", Action: "allow"})
	truncated = truncated[:len(truncated)/2] // torn write: cut mid-JSON
	return [][]byte{v1ok, v1direct, attackLogged, blocked, truncated}
}

func cmdSeed(args []string) error {
	db, _, err := dbFlag(args, false)
	if err != nil {
		return err
	}
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	for i, raw := range scenario() {
		id, err := st.Append(raw)
		if err != nil {
			return err
		}
		fmt.Printf("seeded log %d: format=v%d bytes=%d\n", id, record.Detect(raw), len(raw))
		_ = i
	}
	return nil
}

func cmdRecover(args []string) error {
	db, _, err := dbFlag(args, false)
	if err != nil {
		return err
	}
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	return runRecover(st)
}

func runRecover(st *store.Store) error {
	rep, err := st.Recover()
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	if rep.FirstBadLogID != 0 {
		fmt.Printf("first corrupt state: log %d (quarantined, evidence preserved)\n",
			rep.FirstBadLogID)
	}
	return nil
}

func cmdReplay(args []string) error {
	db, out, err := dbFlag(args, true)
	if err != nil {
		return err
	}
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	return runReplay(st, out)
}

func runReplay(st *store.Store, outPath string) error {
	rep, err := replay.Replay(st, trust.DefaultBoundary())
	if err != nil {
		return err
	}
	ev, err := st.EvidenceRows()
	if err != nil {
		return err
	}
	doc := map[string]any{"replay": rep, "preserved_evidence": ev}
	blob, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(outPath, blob, 0o644); err != nil {
		return err
	}
	fmt.Printf("replayed %d records: %d match, %d diverge\n",
		rep.Total, rep.Matched, rep.Mismatched)
	if rep.FirstError != nil {
		fe := rep.FirstError
		fmt.Printf("FIRST ERROR STATE: log %d field=%s recorded=%q recomputed=%q via %s (%s)\n",
			fe.LogID, fe.Field, fe.Recorded, fe.Recomputed, fe.Rule, fe.Location)
	}
	fmt.Printf("report written to %s (%d evidence artifacts preserved)\n", outPath, len(ev))
	return nil
}

func cmdAll(args []string) error {
	db, out, err := dbFlag(args, true)
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(db); os.IsNotExist(statErr) {
		fmt.Println("== seed ==")
		if err := cmdSeed(args); err != nil {
			return err
		}
	}
	st, err := store.Open(db)
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Println("== recover ==")
	if err := runRecover(st); err != nil {
		return err
	}
	fmt.Println("== replay ==")
	return runReplay(st, out)
}

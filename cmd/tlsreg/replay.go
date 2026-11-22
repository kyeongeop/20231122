package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tlsreg/internal/journal"
	"tlsreg/internal/tlscfg"
)

// cmdReplay re-executes every journaled input of a run and verifies that the
// reproduced results match the recorded ones byte-for-byte.
func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	dbPath := fs.String("db", "", "sqlite journal path")
	runID := fs.String("run", "", "run id to replay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	j, err := journal.Open(*dbPath)
	if err != nil {
		return err
	}
	defer j.Close()
	steps, err := j.LoadSteps(*runID)
	if err != nil {
		return err
	}
	if len(steps) == 0 {
		return fmt.Errorf("no steps found for run %q", *runID)
	}
	mismatch := 0
	for _, s := range steps {
		fn, ok := snapshots[s.Version]
		if !ok {
			return fmt.Errorf("unknown snapshot version %q in journal", s.Version)
		}
		o, _, perr := safeParse(fn, s.InputJSON)
		if perr != nil {
			o = tlscfg.Outcome{Status: "error", Err: s.Version + ": panic: " + perr.Error()}
		}
		if tlscfg.Hash([]byte(s.InputJSON)) != s.InputHash {
			mismatch++
			fmt.Printf("[replay] INPUT HASH MISMATCH seq=%d record=%s\n", s.Seq, s.RecordID)
			continue
		}
		if o.Canonical() != s.Result || o.Status != s.Status {
			mismatch++
			fmt.Printf("[replay] RESULT MISMATCH seq=%d record=%s version=%s\n", s.Seq, s.RecordID, s.Version)
		}
	}
	fmt.Printf("[replay] re-executed %d step(s) of %s: %d mismatch(es)\n", len(steps), *runID, mismatch)
	if mismatch > 0 {
		return fmt.Errorf("replay verification failed with %d mismatches", mismatch)
	}
	fmt.Println("[replay] OK: journal is faithfully replayable")
	return nil
}

// cmdIngestFuzz imports interesting inputs found by the fuzzer into the
// journal as phase "fuzz", so they become part of the same evidence trail.
func cmdIngestFuzz(args []string) error {
	fs := flag.NewFlagSet("ingest-fuzz", flag.ContinueOnError)
	dbPath := fs.String("db", "", "sqlite journal path")
	runID := fs.String("run", "", "run id")
	dir := fs.String("dir", "", "directory with fuzz corpus files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	j, err := journal.Open(*dbPath)
	if err != nil {
		return err
	}
	defer j.Close()
	steps, err := j.LoadSteps(*runID)
	if err != nil {
		return err
	}
	seq := 0
	for _, s := range steps {
		if s.Seq > seq {
			seq = s.Seq
		}
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	imported := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(*dir, e.Name()))
		if err != nil {
			return err
		}
		raw := decodeFuzzFile(string(data))
		if raw == "" {
			continue
		}
		res := map[string]tlscfg.Outcome{}
		for _, ver := range []string{"v1", "v2"} {
			o, _, perr := safeParse(snapshots[ver], raw)
			if perr != nil {
				o = tlscfg.Outcome{Status: "error", Err: ver + ": panic: " + perr.Error()}
			}
			seq++
			_ = j.LogStep(*runID, journal.Step{
				Seq: seq, Phase: "fuzz", RecordID: recordID(raw), Version: ver,
				InputHash: tlscfg.Hash([]byte(raw)), InputJSON: raw,
				Status: o.Status, Result: o.Canonical(), Err: o.Err,
			})
			res[ver] = o
		}
		div := res["v1"].Canonical() != res["v2"].Canonical()
		detail := ""
		if div {
			detail = "FUZZ DIVERGENCE from " + e.Name()
		}
		_ = j.LogComparison(*runID, "fuzz", recordID(raw),
			res["v1"].Canonical(), res["v2"].Canonical(), div, detail)
		imported++
	}
	fmt.Printf("[ingest-fuzz] imported %d fuzz input(s) into run %s\n", imported, *runID)
	return nil
}

// decodeFuzzFile extracts the string value from a Go fuzz corpus file
// (`string("...")` line) produced by `go test -fuzz`.
func decodeFuzzFile(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "string(") {
			inner := strings.TrimSuffix(strings.TrimPrefix(line, "string("), ")")
			var s string
			if _, err := fmt.Sscanf(inner, "%q", &s); err == nil {
				return s
			}
		}
	}
	return ""
}

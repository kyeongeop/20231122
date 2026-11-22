package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tlsreg/internal/journal"
	"tlsreg/internal/tlscfg"
)

type parserFn func([]byte) tlscfg.Outcome

var snapshots = map[string]parserFn{"v1": tlscfg.ParseV1, "v2": tlscfg.ParseV2}

// recordID extracts the id without failing on truncated input.
func recordID(raw string) string {
	const key = `"id":"`
	i := strings.Index(raw, key)
	if i < 0 {
		return "<unparseable>"
	}
	rest := raw[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "<truncated-id>"
	}
	return rest[:j]
}

func safeParse(fn parserFn, raw string) (o tlscfg.Outcome, elapsed time.Duration, err error) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
		elapsed = time.Since(start)
	}()
	o = fn([]byte(raw))
	return o, time.Since(start), nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dbPath := fs.String("db", "", "sqlite journal path")
	artDir := fs.String("artifacts", "artifacts", "evidence output dir")
	seed := fs.Int64("seed", 20231122, "experiment seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		return fmt.Errorf("--db is required")
	}
	if err := os.MkdirAll(*artDir, 0o755); err != nil {
		return err
	}

	// Temporary state for this run; removed in the cleanup phase.
	tmpDir, err := os.MkdirTemp("", "tlsreg-*")
	if err != nil {
		return err
	}
	fmt.Println("[setup] temp state dir:", tmpDir)

	j, err := journal.Open(*dbPath)
	if err != nil {
		return err
	}
	defer j.Close()

	runID := fmt.Sprintf("run-%s", time.Now().UTC().Format("20060102T150405Z"))
	corpus := buildCorpus()
	if err := j.StartRun(runID, *seed, len(corpus), "tls-config-regression"); err != nil {
		return err
	}
	fmt.Println("[setup] run id:", runID)

	if err := writeCorpusEvidence(*artDir, corpus); err != nil {
		return err
	}

	seq := 0
	logStep := func(phase, ver, raw string, o tlscfg.Outcome, elapsed time.Duration) {
		seq++
		s := journal.Step{
			Seq: seq, Phase: phase, RecordID: recordID(raw), Version: ver,
			InputHash: tlscfg.Hash([]byte(raw)), InputJSON: raw,
			Status: o.Status, Result: o.Canonical(), Err: o.Err, Elapsed: elapsed,
		}
		if err := j.LogStep(runID, s); err != nil {
			fmt.Fprintln(os.Stderr, "journal error:", err)
		}
	}

	// process runs one record through both snapshots; never aborts on error.
	process := func(phase, raw string) map[string]tlscfg.Outcome {
		out := map[string]tlscfg.Outcome{}
		for _, ver := range []string{"v1", "v2"} {
			o, elapsed, perr := safeParse(snapshots[ver], raw)
			if perr != nil {
				o = tlscfg.Outcome{Status: "error", Err: ver + ": panic: " + perr.Error()}
			}
			logStep(phase, ver, raw, o, elapsed)
			out[ver] = o
		}
		return out
	}

	// ---- Phase A: baseline ----
	fmt.Println("[phase A] baseline: processing", len(corpus), "records")
	baseline := map[string]map[string]string{}
	errCount := 0
	for _, raw := range corpus {
		res := process("baseline", raw)
		id := recordID(raw)
		baseline[id] = map[string]string{}
		div := res["v1"].Canonical() != res["v2"].Canonical()
		for _, ver := range []string{"v1", "v2"} {
			baseline[id][ver] = res[ver].Canonical()
			if res[ver].Status == "error" {
				errCount++
			}
		}
		detail := ""
		if div {
			detail = "REGRESSION CANDIDATE: snapshots disagree"
		}
		if err := j.LogComparison(runID, "baseline", id,
			res["v1"].Canonical(), res["v2"].Canonical(), div, detail); err != nil {
			return err
		}
	}
	fmt.Printf("[phase A] done: %d snapshot error(s) recorded; processing continued past them\n", errCount)

	// ---- Phase B: order permutation ----
	fmt.Println("[phase B] order-permutation check (seed+1 shuffle)")
	perm := append([]string(nil), corpus...)
	rand.New(rand.NewSource(*seed+1)).Shuffle(len(perm), func(a, b int) { perm[a], perm[b] = perm[b], perm[a] })
	if err := os.WriteFile(filepath.Join(tmpDir, "shuffled-corpus.txt"),
		[]byte(strings.Join(perm, "\n")), 0o644); err != nil {
		return err
	}
	orderViolations := 0
	for _, raw := range perm {
		res := process("order", raw)
		id := recordID(raw)
		for _, ver := range []string{"v1", "v2"} {
			if baseline[id][ver] != res[ver].Canonical() {
				orderViolations++
				_ = j.LogComparison(runID, "order", id, baseline[id][ver], res[ver].Canonical(), true,
					"ORDER VIOLATION: result changed under permutation ("+ver+")")
			}
		}
	}
	fmt.Printf("[phase B] done: %d order-dependence violation(s)\n", orderViolations)

	// ---- Phase C: duplicate submission ----
	fmt.Println("[phase C] duplicate-submission check (each record submitted twice)")
	dupMismatch := 0
	for pass := 1; pass <= 2; pass++ {
		for _, raw := range corpus {
			res := process(fmt.Sprintf("duplicate-pass%d", pass), raw)
			id := recordID(raw)
			for _, ver := range []string{"v1", "v2"} {
				if baseline[id][ver] != res[ver].Canonical() {
					dupMismatch++
					_ = j.LogComparison(runID, "duplicate", id, baseline[id][ver], res[ver].Canonical(), true,
						"DUPLICATE VIOLATION: repeated submission changed result ("+ver+")")
				}
			}
		}
	}
	fmt.Printf("[phase C] done: %d duplicate-submission mismatch(es)\n", dupMismatch)

	// ---- Cleanup ----
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("cleanup temp state: %w", err)
	}
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		return fmt.Errorf("cleanup verification failed: %s still exists", tmpDir)
	}
	fmt.Println("[cleanup] temp state removed and verified:", tmpDir)

	counts, err := j.Counts(runID)
	if err != nil {
		return err
	}
	fmt.Println("[summary]", counts)
	fmt.Println("[done] run id:", runID)
	return nil
}

func writeCorpusEvidence(dir string, corpus []string) error {
	f, err := os.Create(filepath.Join(dir, "corpus.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintln(f, "[")
	for i, raw := range corpus {
		comma := ","
		if i == len(corpus)-1 {
			comma = ""
		}
		fmt.Fprintf(f, "  %q%s\n", raw, comma)
	}
	fmt.Fprintln(f, "]")
	return nil
}

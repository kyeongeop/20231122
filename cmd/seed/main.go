// Command seed runs the DNS name encoding validation pipeline over the
// preserved raw materials (evidence/raw/*.raw) and persists every result —
// anchor offsets, trigger position, permission verdict, evidence — into the
// SQLite database. The fuzz campaign lifecycle is recorded from the real
// libFuzzer log under artifacts/.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"dnscheck/internal/checker"
	"dnscheck/internal/store"
)

func main() {
	dbPath := flag.String("db", "artifacts/dnscheck.db", "SQLite database path")
	rawDir := flag.String("raw", "evidence/raw", "directory of preserved *.raw inputs")
	fuzzLog := flag.String("fuzzlog", "artifacts/fuzz_run1.log", "libFuzzer campaign log")
	fresh := flag.Bool("fresh", true, "recreate all tables before inserting (idempotent re-runs)")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if *fresh {
		if err := st.Reset(); err != nil {
			log.Fatalf("reset store: %v", err)
		}
	}

	if err := seedFuzzRun(st, *fuzzLog); err != nil {
		log.Fatalf("seed fuzz run: %v", err)
	}
	if err := seedEvaluationRun(st, *rawDir); err != nil {
		log.Fatalf("seed evaluation run: %v", err)
	}
	if err := st.VerifyIntegrity(); err != nil {
		log.Fatalf("integrity check failed: %v", err)
	}
	counts, err := st.VerdictCounts()
	if err != nil {
		log.Fatalf("verdict counts: %v", err)
	}
	fmt.Println("seeded:", *dbPath)
	for _, c := range counts {
		fmt.Printf("  verdict %-12s %d case(s)\n", c.Label, c.Count)
	}
}

func tailLog(path string, lines int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(log unavailable: " + err.Error() + ")"
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

func seedFuzzRun(st *store.Store, fuzzLog string) error {
	runID, err := st.CreateRun("libfuzzer-campaign",
		"libFuzzer (clang-18 -fsanitize=fuzzer,address) via Go c-shared bridge")
	if err != nil {
		return err
	}
	excerpt := tailLog(fuzzLog, 12)
	if err := st.AddEvidence(store.Null(), "fuzz_log_tail", excerpt); err != nil {
		return err
	}
	if strings.Contains(excerpt, "Done ") {
		return st.FinishRun(runID, "completed",
			"campaign reached time/run budget without panic or ASan report")
	}
	if err := st.AddAction(runID, 0, "inspect fuzz log and rerun campaign",
		"libFuzzer log lacks a Done marker", "open"); err != nil {
		return err
	}
	return st.FinishRun(runID, "failed", "libFuzzer log lacks a Done marker")
}

func seedEvaluationRun(st *store.Store, rawDir string) error {
	runID, err := st.CreateRun("dns-encoding-validation", "dnscheck/internal/checker.Evaluate")
	if err != nil {
		return err
	}

	matches, err := filepath.Glob(filepath.Join(rawDir, "*.raw"))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return st.FinishRun(runID, "failed", "no raw materials found in "+rawDir)
	}

	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		label := filepath.Base(path)
		res := checker.Evaluate(string(raw))
		if _, err := st.InsertCase(runID, label, string(raw), res); err != nil {
			return fmt.Errorf("insert %s: %w", label, err)
		}
		if res.Verdict == checker.VerdictUndetermined {
			if err := st.AddAction(runID, 0,
				"manually review undetermined edge case: "+label,
				"empty/oversized/malformed input kept as evidence but cannot be auto-judged",
				"open"); err != nil {
				return err
			}
		}
	}
	return st.FinishRun(runID, "completed",
		fmt.Sprintf("evaluated %d preserved raw inputs; integrity verified", len(matches)))
}

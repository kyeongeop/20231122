package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"timeoutfsm/internal/replay"
	"timeoutfsm/internal/report"
	"timeoutfsm/internal/store"
)

func main() {
	root := projectRoot()
	dbPath := filepath.Join(root, "artifacts", "experiment.db")
	evidenceDir := filepath.Join(root, "evidence")

	// Start each experiment run from a clean database for reproducible evidence.
	_ = os.Remove(dbPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		fatal(err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	scenarios := replay.AllScenarios()
	descs := map[string]string{}
	var results []*replay.Result

	for _, sc := range scenarios {
		descs[sc.Name] = sc.Desc
		// Only the baseline recovery performs the single post-recovery replay.
		doReplay := sc.Name == "baseline_recovery" ||
			sc.Name == "unknown_extension_control"
		runID := "run-" + sc.Name
		res, err := replay.Execute(st, runID, sc, doReplay)
		if err != nil {
			fatal(fmt.Errorf("scenario %s: %w", sc.Name, err))
		}
		results = append(results, res)

		if err := writeTrace(evidenceDir, sc.Name, res); err != nil {
			fatal(err)
		}
		fmt.Printf("[run] %-28s steps=%d replay=%v match=%v\n",
			sc.Name, len(res.Steps), res.Replayed, res.ReplayMatch)
	}

	rep := report.Build(dbPath, results, descs)
	if err := rep.WriteJSON(filepath.Join(evidenceDir, "report.json")); err != nil {
		fatal(err)
	}
	if err := rep.WriteMarkdown(filepath.Join(evidenceDir, "report.md")); err != nil {
		fatal(err)
	}

	failed := 0
	for _, v := range rep.Verdicts {
		if !v.AutomatedPass {
			failed++
		}
	}
	fmt.Printf("\nWrote %s\n", dbPath)
	fmt.Printf("Wrote %s, %s\n",
		filepath.Join(evidenceDir, "report.json"),
		filepath.Join(evidenceDir, "report.md"))
	if failed > 0 {
		fmt.Printf("AUTOMATED VERDICT: %d scenario(s) FAILED — see report.md remediation steps.\n", failed)
		os.Exit(1)
	}
	fmt.Println("AUTOMATED VERDICT: all scenarios PASSED. Manual checklist remains in report.md.")
}

func writeTrace(dir, name string, res *replay.Result) error {
	path := filepath.Join(dir, fmt.Sprintf("trace_%s.json", name))
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func projectRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	return wd
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "experiment failed:", err)
	os.Exit(1)
}

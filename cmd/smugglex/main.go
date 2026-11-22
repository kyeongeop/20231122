// Command smugglex reconstructs HTTP request-smuggling runs: it feeds
// extreme-parameter inputs through front-end/back-end parsers over reused
// keep-alive connections, applies the permission policy, and preserves all
// evidence in SQLite.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kyeongeop/20231122/internal/scenario"
	"github.com/kyeongeop/20231122/internal/store"
)

func main() {
	dbPath := flag.String("db", "artifacts/evidence/audit.db", "SQLite evidence database path")
	evidenceDir := flag.String("evidence-dir", "artifacts/evidence/files", "directory for preserved payloads")
	corpusDir := flag.String("corpus-dir", "artifacts/fuzz/corpus", "directory to (re)write seed corpus inputs")
	flag.Parse()

	if err := run(*dbPath, *evidenceDir, *corpusDir); err != nil {
		log.Fatalf("smugglex: %v", err)
	}
}

func run(dbPath, evidenceDir, corpusDir string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	runID, err := st.CreateRun("RUN-smugglex")
	if err != nil {
		return err
	}
	logf := func(level, layer, msg string) {
		if err := st.Log(runID, level, layer, msg); err != nil {
			log.Printf("log persist: %v", err)
		}
	}
	logf("INFO", "cli", fmt.Sprintf("run started db=%s", dbPath))

	for _, sc := range scenario.All() {
		if err := processScenario(st, runID, sc, evidenceDir, corpusDir, logf); err != nil {
			return fmt.Errorf("%s: %w", sc.Name, err)
		}
	}
	logf("INFO", "cli", "run finished")
	return report(st, runID)
}

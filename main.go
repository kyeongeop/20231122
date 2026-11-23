package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"tokenaudit/internal/audit"
)

func main() {
	dbPath := flag.String("db", "audit.db", "SQLite provenance database path")
	outPath := flag.String("out", "report.html", "output path for the provenance check page")
	flag.Parse()
	store, err := audit.OpenStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	p := &audit.Pipeline{
		Store:        store,
		Now:          clock,
		ToolVersion:  "tokenaudit/1.0.0",
		RulesVersion: "prt-rules-2026.11",
	}
	objects := seedObjects(clock)
	runID, err := p.Run(objects)
	if err != nil {
		log.Printf("run finished with warning: %v", err)
	}
	if err := store.RenderReport(runID, *outPath); err != nil {
		log.Fatalf("render report: %v", err)
	}
	fmt.Printf("run #%d done; provenance page written to %s (db: %s)\n", runID, *outPath, *dbPath)
}

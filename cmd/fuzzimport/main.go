package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"tracecheck/internal/store"
)

func main() {
	dbPath := flag.String("db", "data/tracecheck.db", "SQLite database path")
	checkID := flag.String("check", "", "optional check ID to attach evidence to")
	artifactPath := flag.String("artifact", "", "libFuzzer artifact/corpus file")
	logPath := flag.String("log", "", "optional libFuzzer log file")
	minimized := flag.Bool("minimized", false, "artifact is a minimized reproducer")
	flag.Parse()

	if *artifactPath == "" {
		log.Fatal("-artifact is required")
	}
	artifact, err := os.ReadFile(*artifactPath)
	if err != nil {
		log.Fatalf("read artifact: %v", err)
	}
	var fuzzLog []byte
	if *logPath != "" {
		fuzzLog, err = os.ReadFile(*logPath)
		if err != nil {
			log.Fatalf("read log: %v", err)
		}
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	importID, evidenceID, err := st.ImportFuzzArtifact(context.Background(), *checkID, artifact, *minimized, string(fuzzLog))
	if err != nil {
		log.Fatalf("import artifact: %v", err)
	}
	fmt.Printf("imported=%s evidence=%s sha256=%s size=%d\n", importID, evidenceID, store.Hash(artifact), len(artifact))
}

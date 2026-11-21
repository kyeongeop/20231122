// Command audit reconstructs the parser integer-overflow audit: it builds the
// anchor scenarios, runs both parser implementations, records permission
// decisions and preserves all evidence in SQLite plus JSON/log artifacts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyeongeop/20231122/internal/audit"
	"github.com/kyeongeop/20231122/internal/store"
)

func main() {
	base := flag.String("base", ".", "workspace root holding evidence/")
	flag.Parse()

	dbPath := filepath.Join(*base, "evidence", "audit.db")
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open store:", err)
		os.Exit(1)
	}
	defer st.Close()

	report, err := audit.Run(*base, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit run:", err)
		os.Exit(1)
	}

	reportPath := filepath.Join(*base, "evidence", "reports", "report.json")
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal report:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(reportPath, append(raw, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		os.Exit(1)
	}

	count, _ := st.Count()
	fmt.Printf("audit complete: %d cases, %d evidence rows -> %s\n",
		len(report.Cases), count, reportPath)
}

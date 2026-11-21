// Command query reads the audit evidence back out of SQLite and prints a
// compact, human-verifiable chain: case -> anchor -> raw offset -> permission
// -> parser outcome. It is read-only and never modifies preserved evidence.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyeongeop/20231122/internal/store"
)

func main() {
	base := flag.String("base", ".", "workspace root holding evidence/")
	caseID := flag.String("case", "", "optional case id filter")
	flag.Parse()

	st, err := store.Open(filepath.Join(*base, "evidence", "audit.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open store:", err)
		os.Exit(1)
	}
	defer st.Close()

	for _, id := range []string{"CASE-A1", "CASE-A2", "CASE-A3", "CASE-EMPTY", "CASE-OVERSIZE"} {
		if *caseID != "" && *caseID != id {
			continue
		}
		rows, err := st.EvidenceByCase(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "query:", err)
			os.Exit(1)
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Printf("== %s ==\n", id)
		for _, r := range rows {
			fmt.Printf("  [%s] %s anchor=%s raw_off=%d perm=%s wrapped=%q err=%q\n",
				r.EventTime, r.ParserMode, r.Anchor, r.RawOffset,
				r.Permission, r.Wrapped, r.ErrText)
			fmt.Printf("    sha256=%s size=%d file=%s\n",
				r.SHA256, r.InputSize, r.InputPath)
		}
	}
}

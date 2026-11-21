// Command dbtables prints row counts and distinct anchors from the evidence
// database, used as a final structural acceptance check.
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", "evidence/audit.db")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	for _, table := range []string{"evidence", "permission_decisions", "anchor_hits"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			fmt.Fprintln(os.Stderr, table, err)
			os.Exit(1)
		}
		fmt.Printf("%-22s %d rows\n", table, n)
	}
	rows, err := db.Query("SELECT DISTINCT anchor FROM anchor_hits ORDER BY anchor")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rows.Close()
	fmt.Print("anchors: ")
	for rows.Next() {
		var anchor string
		rows.Scan(&anchor)
		fmt.Print(anchor, "  ")
	}
	fmt.Println()
}

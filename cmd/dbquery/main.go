// Command dbquery prints table counts and the ordered event journal so the
// SQLite evidence can be inspected without an external sqlite3 CLI.
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	path := "artifacts/experiment.db"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		fatal(err)
	}
	defer db.Close()

	for _, table := range []string{"runs", "events", "replay_checks"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			fatal(err)
		}
		fmt.Printf("table %-14s rows=%d\n", table, n)
	}

	rows, err := db.Query(`SELECT run_id, seq, kind, accepted, duplicate,
		state_after, substr(hash_after,1,12)
		FROM events ORDER BY run_id, seq`)
	if err != nil {
		fatal(err)
	}
	defer rows.Close()

	fmt.Println("\nordered journal:")
	for rows.Next() {
		var runID, kind, state, hash string
		var seq int
		var accepted, duplicate bool
		if err := rows.Scan(&runID, &seq, &kind, &accepted,
			&duplicate, &state, &hash); err != nil {
			fatal(err)
		}
		fmt.Printf("%-28s seq=%d %-8s accepted=%-5v duplicate=%-5v -> %-13s %s\n",
			runID, seq, kind, accepted, duplicate, state, hash)
	}

	var mismatches int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM replay_checks WHERE match = 0`).Scan(&mismatches); err != nil {
		fatal(err)
	}
	fmt.Printf("\nreplay hash mismatches: %d\n", mismatches)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "dbquery:", err)
	os.Exit(1)
}

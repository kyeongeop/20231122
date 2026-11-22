// Command inspect prints a compact view of the SQLite evidence database:
// run lifecycle events, per-input anchor offsets and retained evidence.
// It exists so the stored evidence can be audited without a sqlite3 CLI.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "artifacts/dnscheck.db", "SQLite database path")
	flag.Parse()
	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println("== runs / lifecycle ==")
	rows, err := db.Query(
		`SELECT r.id, r.name, r.status, r.started_at, r.ended_at,
		        (SELECT COUNT(*) FROM run_events e WHERE e.run_id=r.id)
		 FROM runs r ORDER BY r.id`)
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var id, evts int
		var name, status, started string
		var ended sql.NullString
		if err := rows.Scan(&id, &name, &status, &started, &ended, &evts); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("run#%d %s status=%s events=%d started=%s ended=%s\n",
			id, name, status, evts, started, ended.String)
	}
	rows.Close()

	fmt.Println("\n== inputs / anchors / verdicts ==")
	rows, err = db.Query(
		`SELECT i.id, i.label, i.raw_len, i.sha256,
		        (SELECT COALESCE(GROUP_CONCAT(marker||'@'||marker_off, ' '),'(no anchors)')
		           FROM anchors a WHERE a.input_id=i.id),
		        c.verdict, c.created_at
		 FROM inputs i JOIN conclusions c ON c.input_id=i.id
		 WHERE c.kind='automated' ORDER BY i.id`)
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var id, rawLen int
		var label, sha, anchors, verdict, at string
		if err := rows.Scan(&id, &label, &rawLen, &sha, &anchors, &verdict, &at); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("input#%d %s len=%d verdict=%s at=%s\n  anchors: %s\n  sha256: %s\n",
			id, label, rawLen, verdict, at, anchors, sha)
	}
	rows.Close()

	fmt.Println("\n== evidence labels ==")
	rows, err = db.Query(
		`SELECT i.label, e.label, substr(e.content,1,72)
		 FROM evidence e LEFT JOIN inputs i ON i.id=e.input_id
		 ORDER BY e.id`)
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var input, label, content sql.NullString
		if err := rows.Scan(&input, &label, &content); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%s] %s = %.72s\n", input.String, label.String, content.String)
	}
	rows.Close()

	fmt.Println("\n== next actions ==")
	rows, err = db.Query(`SELECT action, reason, status FROM next_actions ORDER BY id`)
	if err != nil {
		log.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var action, reason, status string
		if err := rows.Scan(&action, &reason, &status); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("- (%s) %s — %s\n", status, action, reason)
		n++
	}
	rows.Close()
	if n == 0 {
		fmt.Println("(none)")
	}
}

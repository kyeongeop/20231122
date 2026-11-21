// Command lfi-query opens a review database and prints the evidence rows and
// the cross-snapshot review view, so reviewers can verify persisted state
// without an external sqlite3 binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"

	"database/sql"
)

func main() {
	dbPath := flag.String("db", "artifacts/review.sqlite", "review database path")
	flag.Parse()

	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+*dbPath+"?mode=ro")
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(2)
	}
	defer db.Close()

	if err := dumpRuns(ctx, db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := dumpEvidence(ctx, db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := dumpPairs(ctx, db); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dumpRuns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx,
		`SELECT run_id, status, object_total, object_failed FROM runs ORDER BY run_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Println("== runs ==")
	for rows.Next() {
		var id, status string
		var total, failed int
		if err := rows.Scan(&id, &status, &total, &failed); err != nil {
			return err
		}
		fmt.Printf("  %s status=%s total=%d failed=%d\n", id, status, total, failed)
	}
	return rows.Err()
}

func dumpEvidence(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT snapshot_version, correlation_id,
		attack_input, trigger_file, trigger_line, permission_decision,
		log_path, log_line, parse_status, length(raw_object)
		FROM evidence ORDER BY snapshot_version, correlation_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Println("\n== evidence (raw bytes retained) ==")
	for rows.Next() {
		var version, corr, attack, file, verdict, logPath, status string
		var line, logLine, rawLen int
		if err := rows.Scan(&version, &corr, &attack, &file, &line,
			&verdict, &logPath, &logLine, &status, &rawLen); err != nil {
			return err
		}
		fmt.Printf("  [%s] %s status=%-9s attack=%q trigger=%s:%d %s log=%s:%d raw=%dB\n",
			version, corr, status, attack, file, line, verdict, logPath, logLine, rawLen)
	}
	return rows.Err()
}

func dumpPairs(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT correlation_id,
		v1_parse_status, v2_parse_status,
		v1_trigger_file, v2_trigger_file,
		v1_permission_decision, v2_permission_decision
		FROM review_pairs ORDER BY correlation_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Println("\n== review_pairs (v1 vs v2) ==")
	for rows.Next() {
		var corr string
		var v1Status, v2Status, v1File, v2File, v1Perm, v2Perm sql.NullString
		if err := rows.Scan(&corr, &v1Status, &v2Status, &v1File, &v2File, &v1Perm, &v2Perm); err != nil {
			return err
		}
		if corr == "" {
			corr = "(no-correlation)"
		}
		fmt.Printf("  %s v1=%-9s v2=%-9s trigger(%s|%s) perm(%s|%s)\n",
			corr, nz(v1Status), nz(v2Status), nz(v1File), nz(v2File), nz(v1Perm), nz(v2Perm))
	}
	return rows.Err()
}

func nz(s sql.NullString) string {
	if !s.Valid || s.String == "" {
		return "-"
	}
	return s.String
}

package pipeline

import (
	"fmt"
	"strings"

	"unicodebypass/internal/store"
)

// Report renders the preserved evidence as a Markdown document.
func Report(db *store.DB) (string, error) {
	var b strings.Builder
	b.WriteString("# Unicode Bypass Pausable Run - Evidence Report\n\n")
	b.WriteString("## Checkpoints\n\n")
	b.WriteString("| run | offset | findings | degraded | digest(8) | created_at |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	err := eachRow(db, `SELECT run_id, offset, findings, degraded, substr(digest,1,8), created_at
		FROM checkpoints ORDER BY rowid`, 6, func(r []string) {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r[0], r[1], r[2], r[3], r[4], r[5])
	})
	if err != nil {
		return "", err
	}

	b.WriteString("\n## Segment Comparison\n\n")
	b.WriteString("| segment | findings | bypasses | degraded |\n")
	b.WriteString("|---|---|---|---|\n")
	err = eachRow(db, `SELECT segment, count(*), sum(bypass), sum(degraded)
		FROM findings GROUP BY segment ORDER BY segment`, 4, func(r []string) {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r[0], r[1], r[2], r[3])
	})
	if err != nil {
		return "", err
	}

	b.WriteString("\n## Digest Comparison\n\n")
	err = eachRow(db, `SELECT c.run_id, c.digest FROM checkpoints c
		WHERE c.offset = (SELECT max(offset) FROM checkpoints WHERE run_id = c.run_id)
		ORDER BY c.run_id`, 2, func(r []string) {
		fmt.Fprintf(&b, "- run %s final cumulative digest: `%s`\n", r[0], r[1])
	})
	if err != nil {
		return "", err
	}

	b.WriteString("\n## Boundary Samples (length boundary)\n\n")
	b.WriteString("| segment | side | item | len | validator_ok | oracle_danger |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	err = eachRow(db, `SELECT segment, side, item_id, len, validator_ok, oracle_danger
		FROM boundary_samples ORDER BY segment, side`, 6, func(r []string) {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r[0], r[1], r[2], r[3], r[4], r[5])
	})
	if err != nil {
		return "", err
	}

	b.WriteString("\n## Degradation Events\n\n")
	err = eachRow(db, `SELECT reason, count(*) FROM degradations GROUP BY reason`, 2, func(r []string) {
		fmt.Fprintf(&b, "- %s: %s events\n", r[0], r[1])
	})
	if err != nil {
		return "", err
	}
	b.WriteString("\n(first 20 events)\n\n")
	b.WriteString("| run | item | reason | at |\n")
	b.WriteString("|---|---|---|---|\n")
	err = eachRow(db, `SELECT run_id, item_id, reason, created_at
		FROM degradations ORDER BY rowid LIMIT 20`, 4, func(r []string) {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r[0], r[1], r[2], r[3])
	})
	if err != nil {
		return "", err
	}

	b.WriteString("\n## Key Evidence: Bypass Findings\n\n")
	b.WriteString("| segment | item | len | name (tail) |\n")
	b.WriteString("|---|---|---|---|\n")
	err = eachRow(db, `SELECT segment, item_id, len, substr(name,-48)
		FROM findings WHERE bypass = 1 ORDER BY item_id LIMIT 40`, 4, func(r []string) {
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` |\n", r[0], r[1], r[2], r[3])
	})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func eachRow(db *store.DB, sql string, ncols int, fn func([]string)) error {
	st, err := db.Prepare(sql)
	if err != nil {
		return err
	}
	defer st.Close()
	for {
		row, err := st.QueryRow(ncols)
		if err != nil {
			return err
		}
		if row == nil {
			return nil
		}
		fn(row)
	}
}

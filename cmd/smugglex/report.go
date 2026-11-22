package main

import (
	"fmt"

	"github.com/kyeongeop/20231122/internal/store"
)

// report prints the reconstruction summary for the run, mapping attack
// input -> trigger location -> permission decision -> log evidence.
func report(st *store.Store, runID int64) error {
	fmt.Printf("== run %d summary ==\n", runID)

	if err := printRows(st, "-- parse results (layer:profile status method path consumed detail)",
		`SELECT layer||':'||profile, status, COALESCE(method,'-'), COALESCE(path,'-'),
		        COALESCE(consumed,0), COALESCE(detail,'')
		 FROM parse_results WHERE run_id=? ORDER BY id`, runID); err != nil {
		return err
	}
	if err := printRows(st, "-- smuggled requests (method path sha256 evidence)",
		`SELECT method, path, substr(sha256,1,16), COALESCE(evidence_path,'')
		 FROM smuggled_requests WHERE run_id=? ORDER BY id`, runID); err != nil {
		return err
	}
	if err := printRows(st, "-- permissions (path identity decision reason)",
		`SELECT path, identity, decision, COALESCE(reason,'')
		 FROM permissions WHERE run_id=? ORDER BY id`, runID); err != nil {
		return err
	}
	if err := printRows(st, "-- boundaries (parameter limit side size status)",
		`SELECT parameter, limit_value, side, size, status
		 FROM boundaries WHERE run_id=? ORDER BY id`, runID); err != nil {
		return err
	}
	if err := printRows(st, "-- alert/warn logs (level layer message)",
		`SELECT level, layer, message FROM logs
		 WHERE run_id=? AND level IN ('ALERT','WARN') ORDER BY id`, runID); err != nil {
		return err
	}
	return nil
}

func printRows(st *store.Store, title, query string, args ...any) error {
	fmt.Println(title)
	rows, err := st.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		fmt.Printf("  ")
		for i, v := range vals {
			if i > 0 {
				fmt.Printf(" | ")
			}
			fmt.Printf("%v", v)
		}
		fmt.Println()
		n++
	}
	if n == 0 {
		fmt.Println("  (none)")
	}
	return rows.Err()
}

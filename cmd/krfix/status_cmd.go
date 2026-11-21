package main

import (
	"flag"
	"fmt"

	"krfix/internal/material"
)

func runStatus(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	if err := printMeta(ctx, db); err != nil {
		return err
	}
	fmt.Println("\nanchors (raw offsets into original material):")
	offsets, err := printAnchors(ctx, db)
	if err != nil {
		return err
	}

	fmt.Println("\njobs:")
	rows, err := db.QueryContext(ctx,
		`SELECT s.name,s.kind,j.phase,j.state,j.attempts,
		        COALESCE(r.verdict_label,'-'),COALESCE(r.exit_code,'-'),
		        COALESCE(r.started_at_utc,'-'),COALESCE(r.finished_at_utc,'-')
		 FROM samples s
		 JOIN jobs j ON j.sample_id=s.id
		 LEFT JOIN runs r ON r.job_id=j.id AND
		      r.id=(SELECT MAX(id) FROM runs WHERE job_id=j.id)
		 ORDER BY s.name,j.phase`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Printf("  %-18s %-6s %-5s %-11s %-3s %-26s %-4s %-30s %s\n",
		"sample", "kind", "phase", "state", "att", "verdict", "exit", "started_utc", "finished_utc")
	for rows.Next() {
		var name, kind, phase, state, label, started, finished string
		var attempts int
		var exit any
		if err := rows.Scan(&name, &kind, &phase, &state, &attempts,
			&label, &exit, &started, &finished); err != nil {
			return err
		}
		fmt.Printf("  %-18s %-6s %-5s %-11s %-3d %-26s %-4v %-30s %s\n",
			name, kind, phase, state, attempts, label, exit, started, finished)
	}

	fmt.Println("\nsample anchor offsets:")
	srows, err := db.QueryContext(ctx,
		`SELECT name,anchor1_offset,anchor2_offset,anchor3_offset,
		        client_epoch,server_epoch,attest_epoch
		 FROM samples ORDER BY name`)
	if err != nil {
		return err
	}
	defer srows.Close()
	for srows.Next() {
		var name string
		var o1, o2, o3, ce, se, ae int64
		if err := srows.Scan(&name, &o1, &o2, &o3, &ce, &se, &ae); err != nil {
			return err
		}
		fmt.Printf("  %-18s offsets=[%d,%d,%d] epochs(c/s/a)=%d/%d/%d\n",
			name, o1, o2, o3, ce, se, ae)
	}
	_ = offsets
	return srows.Err()
}

package main

import (
	"context"
	"database/sql"
	"fmt"
)

func printMeta(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx,
		`SELECT key,value,updated_at_utc FROM run_meta ORDER BY key`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Println("workspace meta:")
	for rows.Next() {
		var k, v, t string
		if err := rows.Scan(&k, &v, &t); err != nil {
			return err
		}
		fmt.Printf("  %-16s %-70s updated=%s\n", k, v, t)
	}
	return rows.Err()
}

func printAnchors(ctx context.Context, db *sql.DB) ([3]int64, error) {
	var offsets [3]int64
	rows, err := db.QueryContext(ctx,
		`SELECT anchor_index,magic,name,raw_offset,length,located_at_utc
		 FROM anchors ORDER BY anchor_index`)
	if err != nil {
		return offsets, err
	}
	defer rows.Close()
	for rows.Next() {
		var idx int
		var magic, name, at string
		var off, length int64
		if err := rows.Scan(&idx, &magic, &name, &off, &length, &at); err != nil {
			return offsets, err
		}
		offsets[idx-1] = off
		fmt.Printf("  #%d %s %-11s raw_offset=%-4d length=%d located_at=%s\n",
			idx, magic, name, off, length, at)
	}
	return offsets, rows.Err()
}

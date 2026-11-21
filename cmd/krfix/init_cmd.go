package main

import (
	"flag"
	"fmt"

	"krfix/internal/material"
	"krfix/internal/store"
)

func runInit(layout material.Layout, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	force := fs.Bool("force", false, "reuse existing database without resealing original")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	if err := store.SetMeta(ctx, db, "krfix_version", version); err != nil {
		return err
	}

	raw, anchors, sealErr := material.SealOriginal(ctx, layout, db)
	if sealErr != nil {
		if !*force {
			return sealErr
		}
		fmt.Println("krfix: original material already sealed, keeping untouched copy")
	} else {
		fmt.Printf("krfix: sealed original material (%d bytes, sha256=%s)\n",
			len(raw), material.SHA256Hex(raw))
	}

	for _, a := range anchors {
		fmt.Printf("  anchor #%d %-8s %-11s raw_offset=%d length=%d\n",
			a.Index, a.Magic, a.Name, a.Offset, a.Length)
	}
	fmt.Println("krfix: workspace initialized at", layout.Root)
	return nil
}

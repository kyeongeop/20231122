package main

import (
	"flag"
	"fmt"

	"krfix/internal/material"
)

func runVerify(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	if err := material.VerifyOriginal(ctx, layout, db); err != nil {
		return err
	}
	pinned, err := material.PinnedHash(ctx, layout, db)
	if err != nil {
		return err
	}
	fmt.Printf("krfix: original material intact sha256=%s mode=0444\n", pinned)
	return nil
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"krfix/internal/evidence"
	"krfix/internal/material"
)

func runReport(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	sample := fs.String("sample", "", "sample name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sample == "" {
		return fmt.Errorf("--sample is required")
	}
	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	rep, err := evidence.BuildReport(ctx, db, *sample)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func runExport(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	sample := fs.String("sample", "", "sample name (required)")
	outDir := fs.String("out", "", "export directory (default .krfix/export/<sample>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sample == "" {
		return fmt.Errorf("--sample is required")
	}
	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	rep, err := evidence.BuildReport(ctx, db, *sample)
	if err != nil {
		return err
	}
	dir := *outDir
	if dir == "" {
		dir = layout.Root + "/export/" + *sample
	}
	reportPath, err := evidence.WriteJSON(rep, dir, *sample)
	if err != nil {
		return err
	}
	bundlePath := dir + "/" + *sample + "_evidence.tar.gz"
	if err := evidence.Bundle(rep, reportPath, bundlePath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "krfix: report %s\nkrfix: bundle %s\n",
		reportPath, bundlePath)
	return nil
}

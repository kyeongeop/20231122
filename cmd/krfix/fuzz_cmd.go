package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"krfix/internal/material"
	"krfix/internal/runner"
)

func runFuzz(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	phase := fs.String("phase", "vuln", "vuln|fixed")
	seconds := fs.Int("seconds", 20, "libFuzzer -max_total_time")
	maxLen := fs.Int("max-len", 128, "libFuzzer -max_len")
	seedCorpus := fs.String("seed-corpus", "", "seed directory (default working corpus)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bin := layout.BuildDir + "/kr_fuzz_" + *phase
	corpus := filepath.Join(layout.Root, "fuzz", *phase, "corpus")
	artifacts := filepath.Join(layout.Root, "fuzz", *phase, "artifacts")
	logs := filepath.Join(layout.EvidenceDir, "_fuzz", *phase)
	if *seedCorpus == "" {
		*seedCorpus = layout.CorpusDir
	}

	// Seed the libFuzzer corpus from the working corpus so the campaign
	// starts from valid three-anchor frames.
	if err := seedLibFuzzerCorpus(*seedCorpus, corpus); err != nil {
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

	cfg := runner.CampaignConfig{
		Binary:      bin,
		CorpusDir:   corpus,
		ArtifactDir: artifacts,
		MaxTotalSec: *seconds,
		MaxLen:      *maxLen,
		Jobs:        1,
	}
	res, err := runner.RunCampaign(ctx, cfg, logs, *phase)
	if err != nil {
		return err
	}
	fmt.Printf("krfix: libFuzzer %s exit=%d corpus_entries=%d crash_files=%d\n",
		*phase, res.ExitCode, res.CorpusEntries, len(res.CrashFiles))
	for _, c := range res.CrashFiles {
		fmt.Println("  crash:", c)
	}
	fmt.Println("  logs:", res.StdoutLog, res.StderrLog)
	return nil
}

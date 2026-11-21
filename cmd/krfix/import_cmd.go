package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"krfix/internal/material"
	"krfix/internal/store"
)

func friendlyImportErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("sample name already imported (choose a different --name): %w", err)
	}
	return err
}

func runImport(layout material.Layout, args []string) error {
	requireInit(layout)
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	seed := fs.Bool("seed", true, "import the deterministic built-in corpus")
	filePath := fs.String("file", "", "import one raw frame file instead of the seed corpus")
	name := fs.String("name", "", "sample name required with --file")
	kind := fs.String("kind", "attack", "attack|benign (used with --file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, ctx, cancel, err := openDB(layout)
	if err != nil {
		return err
	}
	defer cancel()
	defer db.Close()

	if *filePath != "" {
		if *name == "" {
			return fmt.Errorf("--name is required with --file")
		}
		content, err := os.ReadFile(*filePath)
		if err != nil {
			return err
		}
		s, err := material.ImportSample(ctx, layout, db, *name, *kind, content)
		if err != nil {
			return friendlyImportErr(err)
		}
		printSampleRow(s)
		return nil
	}

	if !*seed {
		return fmt.Errorf("nothing to import (use --seed or --file)")
	}
	for _, sd := range material.CorpusSeeds() {
		s, err := material.ImportSample(ctx, layout, db, sd.Name, sd.Kind, sd.Build())
		if err != nil {
			return friendlyImportErr(fmt.Errorf("import %s: %w", sd.Name, err))
		}
		printSampleRow(s)
	}
	fmt.Printf("krfix: imported %d samples into %s\n",
		len(material.CorpusSeeds()), layout.CorpusDir)
	return nil
}

func printSampleRow(s *store.Sample) {
	fmt.Printf("  %-18s %-6s sha256=%.12s... offsets=[%d,%d,%d] epochs(c/s/a)=%d/%d/%d\n",
		s.Name, s.Kind, s.SHA256,
		s.AnchorOffsets[0], s.AnchorOffsets[1], s.AnchorOffsets[2],
		s.ClientEpoch, s.ServerEpoch, s.AttestEpoch)
}

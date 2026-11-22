package main

import (
	"context"
	"errors"
	"fmt"

	"apiskew.local/apiskew/internal/bundle"
)

func (c *cli) exportBundle(ctx context.Context, args []string) error {
	flags := newFlagSet("export", c.stderr)
	sessionFlag := flags.String("session", "", "session id (default: latest)")
	sampleFlag := flags.String("sample", "", "export one sample id")
	outDir := flags.String("out", "", "new bundle directory")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outDir == "" {
		return errors.New("--out is required")
	}
	st, err := c.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	sessionID, err := c.sessionID(ctx, st, *sessionFlag)
	if err != nil {
		return err
	}
	manifest, err := bundle.Export(ctx, st, bundle.ExportOptions{
		SessionID: sessionID,
		SampleID:  *sampleFlag,
		OutDir:    *outDir,
	})
	if err != nil {
		return err
	}
	if *jsonOut {
		return emitJSON(c.stdout, manifest)
	}
	fmt.Fprintf(c.stdout, "bundle exported: %s\n", *outDir)
	fmt.Fprintf(c.stdout, "session: %s\n", manifest.Session.ID)
	fmt.Fprintf(c.stdout, "records: %d\n", manifest.RecordCount)
	fmt.Fprintf(c.stdout, "verify: cd %s && sha256sum -c SHA256SUMS && apiskew verify-bundle .\n", *outDir)
	return nil
}

func (c *cli) verifyBundle(args []string) error {
	flags := newFlagSet("verify-bundle", c.stderr)
	sample := flags.String("sample", "", "verify one sample only")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(flagFirst(args)); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("verify-bundle accepts at most one directory")
	}
	dir := "."
	if flags.NArg() == 1 {
		dir = flags.Arg(0)
	}
	result, err := bundle.Verify(bundle.VerifyOptions{Dir: dir, SampleID: *sample})
	if err != nil {
		return err
	}
	if *jsonOut {
		return emitJSON(c.stdout, result)
	}
	fmt.Fprintf(c.stdout, "verified bundle=%s session=%s records=%d checked=%d attempts=%d\n",
		result.BundleSchema, result.SessionID, result.RecordCount, result.CheckedCount, result.AttemptCount)
	return nil
}

func flagFirst(args []string) []string {
	flagArgs := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--sample" || arg == "--json":
			flagArgs = append(flagArgs, arg)
			if arg == "--sample" && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
		case len(arg) > 9 && arg[:9] == "--sample=":
			flagArgs = append(flagArgs, arg)
		default:
			positional = append(positional, arg)
		}
	}
	return append(flagArgs, positional...)
}

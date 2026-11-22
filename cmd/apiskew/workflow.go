package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"apiskew.local/apiskew/internal/app"
)

type discoverSummary struct {
	SessionID      string   `json:"session_id"`
	Status         string   `json:"status"`
	Imported       int      `json:"imported"`
	Duplicates     int      `json:"duplicates"`
	FalsePositives int      `json:"false_positives"`
	Invalid        int      `json:"invalid"`
	SampleIDs      []string `json:"sample_ids"`
	FindingsDir    string   `json:"findings_dir"`
	CorpusDir      string   `json:"corpus_dir"`
	LogPath        string   `json:"log_path"`
	FuzzerSHA256   string   `json:"fuzzer_sha256"`
	Command        []string `json:"fuzzer_command"`
	DurationMS     int64    `json:"duration_ms"`
	Interrupted    bool     `json:"interrupted"`
}

func (c *cli) discover(ctx context.Context, args []string) error {
	flags := newFlagSet("discover", c.stderr)
	sessionFlag := flags.String("session", "", "session id (default: latest)")
	fuzzer := flags.String("fuzzer", envDefault("APISKEW_FUZZER", "./build/apiskew_fuzz"), "libFuzzer executable")
	workDir := flags.String("work", "", "persistent corpus/findings directory")
	seconds := flags.Int("seconds", 10, "libFuzzer time budget")
	maxFindings := flags.Int("max-findings", 5000, "new samples per run and native finding-file cap")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
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
	if *workDir == "" {
		*workDir = filepath.Join("artifacts", "sessions", sessionID, "fuzz")
	}
	result, discoverErr := app.Discover(ctx, st, app.DiscoverOptions{
		SessionID:   sessionID,
		Fuzzer:      *fuzzer,
		WorkDir:     *workDir,
		Seconds:     *seconds,
		MaxFindings: *maxFindings,
	})
	summary := discoverSummary{
		SessionID:      sessionID,
		Status:         result.Status,
		Imported:       result.Imported,
		Duplicates:     result.Duplicates,
		FalsePositives: result.FalsePositives,
		Invalid:        result.Invalid,
		SampleIDs:      result.SampleIDs,
		FindingsDir:    result.Fuzzer.FindingsDir,
		CorpusDir:      result.Fuzzer.CorpusDir,
		LogPath:        result.Fuzzer.LogPath,
		FuzzerSHA256:   result.Fuzzer.FuzzerSHA256,
		Command:        result.Fuzzer.Command,
		DurationMS:     result.Fuzzer.DurationMS,
		Interrupted:    result.Fuzzer.Interrupted || errors.Is(discoverErr, context.Canceled),
	}
	if *jsonOut {
		if err := emitJSON(c.stdout, summary); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(c.stdout, "discover session=%s status=%s imported=%d duplicates=%d mismatches=%d invalid=%d\n",
			summary.SessionID, summary.Status, summary.Imported, summary.Duplicates,
			summary.FalsePositives, summary.Invalid)
		fmt.Fprintf(c.stdout, "findings: %s\ncorpus: %s\nlog: %s\nfuzzer_sha256: %s\n",
			summary.FindingsDir, summary.CorpusDir, summary.LogPath, summary.FuzzerSHA256)
	}
	return discoverErr
}

func (c *cli) replay(ctx context.Context, args []string) error {
	flags := newFlagSet("replay", c.stderr)
	sessionFlag := flags.String("session", "", "session id (default: latest)")
	sample := flags.String("sample", "all", "sample id or all")
	engine := flags.String("engine", envDefault("APISKEW_REPLAY_ENGINE", "go"), "go or go+libfuzzer")
	fuzzer := flags.String("fuzzer", envDefault("APISKEW_FUZZER", "./build/apiskew_fuzz"), "libFuzzer executable")
	workDir := flags.String("work", "", "oracle work directory")
	repeat := flags.Int("repeat", 1, "replays per sample")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
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
	if *workDir == "" {
		*workDir = filepath.Join("artifacts", "sessions", sessionID, "replay")
	}
	result, replayErr := app.Replay(ctx, st, app.ReplayOptions{
		SessionID: sessionID,
		SampleID:  *sample,
		Engine:    *engine,
		Fuzzer:    *fuzzer,
		WorkDir:   *workDir,
		Repeat:    *repeat,
	})
	if *jsonOut {
		if err := emitJSON(c.stdout, result); err != nil {
			return err
		}
	} else {
		for _, item := range result.Runs {
			fmt.Fprintf(c.stdout, "%s attempt=%d engine=%s status=%s v1=%t v2=%t diff=%t evidence=%s\n",
				item.SampleID, item.Attempt, item.Engine, item.Status, item.V1Allow,
				item.V2Allow, item.PermissionDifference, item.EvidenceSHA256[:12])
		}
	}
	return replayErr
}

func (c *cli) compare(ctx context.Context, args []string) error {
	flags := newFlagSet("compare", c.stderr)
	sessionFlag := flags.String("session", "", "session id (default: latest)")
	sample := flags.String("sample", "", "one sample id (default: all)")
	jsonOut := flags.Bool("json", false, "emit JSON")
	failDrift := flags.Bool("fail-on-drift", false, "return an error if attempts differ")
	if err := flags.Parse(args); err != nil {
		return err
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
	result, err := app.Compare(ctx, st, sessionID, *sample)
	if err != nil {
		return err
	}
	if *jsonOut {
		if err := emitJSON(c.stdout, result); err != nil {
			return err
		}
	} else {
		for _, sample := range result.Samples {
			fmt.Fprintf(c.stdout, "%s attempts=%d first=%d latest=%d v1=%t v2=%t diff=%t stable=%t drift=%s\n",
				sample.SampleID, sample.Attempts, sample.FirstAttempt, sample.LatestAttempt,
				sample.V1Allow, sample.V2Allow, sample.PermissionDifference, sample.Stable,
				joinOrDash(sample.DriftFields))
		}
	}
	if *failDrift {
		for _, sample := range result.Samples {
			if !sample.Stable {
				return fmt.Errorf("replay drift detected for %s: %s", sample.SampleID, joinOrDash(sample.DriftFields))
			}
		}
	}
	return nil
}

func (c *cli) fix(ctx context.Context, args []string) error {
	flags := newFlagSet("fix", c.stderr)
	sessionFlag := flags.String("session", "", "session id (default: latest)")
	sample := flags.String("sample", "", "sample id")
	outPath := flags.String("out", "", "write the verified fix plan JSON")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *sample == "" {
		return errors.New("--sample is required")
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
	result, err := app.Fix(ctx, st, sessionID, *sample)
	if err != nil {
		return err
	}
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			return err
		}
		if err := writeIndentedJSON(*outPath, result); err != nil {
			return err
		}
	}
	if *jsonOut {
		return emitJSON(c.stdout, result)
	}
	fmt.Fprintf(c.stdout, "sample          %s\n", result.SampleID)
	fmt.Fprintf(c.stdout, "root cause      %s\n", result.Plan.RootCause)
	fmt.Fprintf(c.stdout, "rule            %s (%s)\n", result.Plan.RuleID, result.Plan.Scope)
	fmt.Fprintf(c.stdout, "before v1       allow=%t\n", result.Plan.BeforeV1Allow)
	fmt.Fprintf(c.stdout, "after v1 patch  allow=%t\n", result.Plan.AfterV1Allow)
	fmt.Fprintf(c.stdout, "v2 control      allow=%t\n", result.Plan.V2Allow)
	fmt.Fprintf(c.stdout, "verified        %t after %d deterministic runs\n", result.Plan.Verified, result.StableRuns)
	fmt.Fprintf(c.stdout, "summary         %s\n", result.Plan.Summary)
	return nil
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	out := values[0]
	for _, value := range values[1:] {
		out += "," + value
	}
	return out
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeIndentedJSON(path string, value any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := emitJSON(file, value); err != nil {
		return err
	}
	return file.Sync()
}

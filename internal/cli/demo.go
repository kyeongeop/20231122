package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"auditfix/internal/audit"
	"auditfix/internal/db"
	"auditfix/internal/model"
	"auditfix/internal/runner"
)

type demoLogEvent struct {
	Seq           int64  `json:"seq"`
	Device        string `json:"device"`
	TimeUnixNS    int64  `json:"time_unix_ns"`
	Kind          string `json:"kind"`
	AnchorID      string `json:"anchor_id"`
	Subject       string `json:"subject"`
	PayloadSHA256 string `json:"payload_sha256"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

type sampleEvent struct {
	device    string
	seq       int64
	time      int64
	kind      string
	anchor    string
	subject   string
	payload   string
	breakPrev bool
}

var demoExpected = map[string]string{
	"01-valid-baseline.sample":     "OK",
	"02-clock-skew-only.sample":    "CLOCK_SKEW",
	"03-missing-segment.sample":    "MISSING_SEGMENT",
	"04-clock-skew-missing.sample": "MISSING_SEGMENT",
	"05-chain-tamper.sample":       "CHAIN_BREAK",
	"06-anchor-mismatch.sample":    "ANCHOR_MISMATCH",
	"07-malformed.sample":          "MALFORMED",
	"08-duplicate-sequence.sample": "CHAIN_BREAK",
}

func (a *App) demo(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	dir := flags.String("dir", "demo", "demo output directory")
	force := flags.Bool("force", false, "replace an existing demo directory")
	harness := flags.String("harness", filepath.Join("build", "auditfix_harness"),
		"libFuzzer harness executable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	target, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if err := requirePath("harness", *harness); err != nil {
		return err
	}
	harnessAbs, err := filepath.Abs(*harness)
	if err != nil {
		return err
	}
	if _, err := os.Stat(harnessAbs); err != nil {
		return fmt.Errorf("harness unavailable: %w (run 'make harness')", err)
	}
	if info, err := os.Stat(target); err == nil {
		if !*force {
			return fmt.Errorf("demo directory %q already exists; use --force", *dir)
		}
		if info.IsDir() {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("demo target %q is not a directory", *dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Join(target, "corpus"), 0o755); err != nil {
		return err
	}
	logA, err := buildAuditLog("device-a", 0, map[int64]bool{5: true, 6: true})
	if err != nil {
		return err
	}
	logB, err := buildAuditLog("device-b", 30*time.Second, nil)
	if err != nil {
		return err
	}
	pathA := filepath.Join(target, "device-a.jsonl")
	pathB := filepath.Join(target, "device-b.jsonl")
	if err := os.WriteFile(pathA, logA, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(pathB, logB, 0o644); err != nil {
		return err
	}
	if err := writeDemoCorpus(filepath.Join(target, "corpus")); err != nil {
		return err
	}

	dbPath := filepath.Join(target, "auditfix.sqlite")
	caseID := "clock-desync-demo"
	runID := "demo-run"
	fmt.Fprintln(a.Stdout, "== import two unsynchronised device logs ==")
	if err := a.caseImport(ctx, []string{
		"--db", dbPath, "--case-id", caseID,
		"--a", pathA, "--b", pathB,
		"--description", "device-b clock leads device-a by 30s; device-a has a sealed missing segment seq 5-6",
	}); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== import attack corpus ==")
	if err := a.sampleImport(ctx, []string{
		"--db", dbPath, "--case-id", caseID,
		"--dir", filepath.Join(target, "corpus"),
	}); err != nil {
		return err
	}

	fmt.Fprintln(a.Stdout, "\n== first invocation: pause after two samples ==")
	if err := a.runSamples(ctx, []string{
		"--db", dbPath, "--case-id", caseID, "--harness", harnessAbs,
		"--run-id", runID, "--limit", "2", "--timeout", "5s",
	}, false); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== resume invocation ==")
	if err := a.runSamples(ctx, []string{
		"--db", dbPath, "--run-id", runID, "--timeout", "5s",
	}, true); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== replay the clock+gap sample independently ==")
	if err := a.replaySample(ctx, []string{
		"--db", dbPath, "--run-id", runID,
		"--sample", "04-clock-skew-missing.sample", "--timeout", "5s",
	}); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== compare first and latest attempts ==")
	if err := a.compareRuns(ctx, []string{
		"--db", dbPath, "--run-id", runID,
	}); err != nil {
		return err
	}
	if err := checkDemoExpectations(ctx, dbPath, caseID, runID); err != nil {
		return err
	}
	bundleDir := filepath.Join(target, "bundle")
	fmt.Fprintln(a.Stdout, "\n== export deterministic review bundle ==")
	if err := a.exportBundle(ctx, []string{
		"--db", dbPath, "--run-id", runID, "--out", bundleDir,
	}); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== verify bundle and embedded evidence ==")
	if err := a.verifyBundle(ctx, []string{"--bundle", bundleDir}); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "\n== independently rerun every attack sample ==")
	if err := a.verifyBundle(ctx, []string{
		"--bundle", bundleDir, "--rerun", "--harness", harnessAbs,
	}); err != nil {
		return err
	}
	restored := filepath.Join(target, "restored.sqlite")
	fmt.Fprintln(a.Stdout, "\n== restore SQLite artifact ==")
	if err := a.restoreBundle(ctx, []string{
		"--bundle", bundleDir, "--db", restored,
	}); err != nil {
		return err
	}
	store, err := db.OpenReadOnly(restored)
	if err != nil {
		return err
	}
	restoredRun, err := store.GetRun(ctx, runID)
	store.Close()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "restored run=%s case=%s status=%s attempts=%d\n",
		restoredRun.RunID, restoredRun.CaseID, restoredRun.Status,
		restoredRun.AttemptCount)
	fmt.Fprintf(a.Stdout, "\ndemo complete: %s\n", target)
	return nil
}

func buildAuditLog(device string, skew time.Duration, missing map[int64]bool) ([]byte, error) {
	const base int64 = 1763772000000000000
	var events []demoLogEvent
	lastHash := strings.Repeat("0", 64)
	for seq := int64(1); seq <= 10; seq++ {
		if missing[seq] {
			continue
		}
		kind, anchor, subject := "operation", "", "file.write"
		if seq == 1 || seq == 4 || seq == 7 || seq == 10 {
			kind = "anchor"
			anchor = fmt.Sprintf("beacon-%d", (seq+2)/3)
			subject = "clock.sync"
		}
		payload := sha256Hex([]byte(fmt.Sprintf("%s:%d:%s", device, seq, subject)))
		if kind == "anchor" {
			payload = sha256Hex([]byte("beacon:" + anchor))
		}
		timeNS := base + (seq-1)*int64(10*time.Second) + int64(skew)
		hash := audit.HashEvent(device, seq, timeNS, kind, anchor, subject, payload, lastHash)
		events = append(events, demoLogEvent{
			Seq: seq, Device: device, TimeUnixNS: timeNS, Kind: kind,
			AnchorID: anchor, Subject: subject, PayloadSHA256: payload,
			PrevHash: lastHash, RecordHash: hash,
		})
		lastHash = hash
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func writeDemoCorpus(dir string) error {
	samples, err := demoCorpus()
	if err != nil {
		return err
	}
	for name, data := range samples {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func demoCorpus() (map[string][]byte, error) {
	const base int64 = 1763772000000000000
	anchor := func(id string) string { return sha256Hex([]byte("beacon:" + id)) }
	op := func(name string) string { return sha256Hex([]byte("op:" + name)) }
	standard := func(skew int64, missingA map[int64]bool) []sampleEvent {
		var events []sampleEvent
		for seq := int64(1); seq <= 5; seq++ {
			if !missingA[seq] {
				kind, id, subject := "operation", "", "auth.verify"
				if seq == 1 || seq == 5 {
					kind, id, subject = "anchor", "beacon-standard", "clock.sync"
				}
				payload := op(fmt.Sprintf("a-%d", seq))
				if kind == "anchor" {
					payload = anchor(id)
				}
				events = append(events, sampleEvent{
					device: "a", seq: seq, time: base + seq*int64(time.Second),
					kind: kind, anchor: id, subject: subject, payload: payload,
				})
			}
		}
		for seq := int64(1); seq <= 5; seq++ {
			kind, id, subject := "operation", "", "auth.verify"
			if seq == 1 || seq == 5 {
				kind, id, subject = "anchor", "beacon-standard", "clock.sync"
			}
			payload := op(fmt.Sprintf("b-%d", seq))
			if kind == "anchor" {
				payload = anchor(id)
			}
			events = append(events, sampleEvent{
				device: "b", seq: seq, time: base + seq*int64(time.Second) + skew,
				kind: kind, anchor: id, subject: subject, payload: payload,
			})
		}
		return events
	}
	samples := map[string][]byte{
		"01-valid-baseline.sample":     renderSample(standard(0, nil)),
		"02-clock-skew-only.sample":    renderSample(standard(10*int64(time.Second), nil)),
		"03-missing-segment.sample":    renderSample(standard(0, map[int64]bool{3: true, 4: true})),
		"04-clock-skew-missing.sample": renderSample(standard(10*int64(time.Second), map[int64]bool{3: true, 4: true})),
		"07-malformed.sample":          []byte("not-an-audit-sample\n"),
	}

	tamper := []sampleEvent{
		{device: "a", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-tamper", subject: "clock.sync", payload: anchor("beacon-tamper")},
		{device: "a", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("tamper-2")},
		{device: "a", seq: 3, time: base + 3e9, kind: "operation", subject: "auth.verify", payload: op("tamper-3"), breakPrev: true},
		{device: "b", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-tamper", subject: "clock.sync", payload: anchor("beacon-tamper")},
		{device: "b", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("tamper-b-2")},
	}
	samples["05-chain-tamper.sample"] = renderSample(tamper)

	mismatch := []sampleEvent{
		{device: "a", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-mismatch", subject: "clock.sync", payload: anchor("left")},
		{device: "a", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("mismatch-a")},
		{device: "b", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-mismatch", subject: "clock.sync", payload: anchor("right")},
		{device: "b", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("mismatch-b")},
	}
	samples["06-anchor-mismatch.sample"] = renderSample(mismatch)

	duplicate := []sampleEvent{
		{device: "a", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-duplicate", subject: "clock.sync", payload: anchor("beacon-duplicate")},
		{device: "a", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("dup-2a")},
		{device: "a", seq: 2, time: base + 3e9, kind: "operation", subject: "auth.verify", payload: op("dup-2b")},
		{device: "b", seq: 1, time: base + 1e9, kind: "anchor", anchor: "beacon-duplicate", subject: "clock.sync", payload: anchor("beacon-duplicate")},
		{device: "b", seq: 2, time: base + 2e9, kind: "operation", subject: "auth.verify", payload: op("dup-b")},
	}
	samples["08-duplicate-sequence.sample"] = renderSample(duplicate)
	return samples, nil
}

func renderSample(events []sampleEvent) []byte {
	var buf bytes.Buffer
	buf.WriteString("AFXS1\n")
	last := map[string]string{"a": strings.Repeat("0", 64), "b": strings.Repeat("0", 64)}
	for _, event := range events {
		prev := last[event.device]
		if event.breakPrev {
			prev = strings.Repeat("0", 64)
		}
		deviceName := "device-" + event.device
		hash := audit.HashEvent(deviceName, event.seq, event.time, event.kind,
			event.anchor, event.subject, event.payload, prev)
		fmt.Fprintf(&buf, "D\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			event.device, event.seq, event.time, event.kind, event.anchor,
			event.subject, event.payload, prev, hash)
		last[event.device] = hash
	}
	return buf.Bytes()
}

func checkDemoExpectations(ctx context.Context, dbPath, caseID, runID string) error {
	store, err := db.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	samples, err := store.ListSamples(ctx, caseID)
	if err != nil {
		return err
	}
	attempts, err := store.ListAttempts(ctx, runID)
	if err != nil {
		return err
	}
	latest := latestTerminalBySampleMap(attempts)
	for _, sample := range samples {
		want, ok := demoExpected[sample.Name]
		if !ok {
			return fmt.Errorf("no expected classification for %s", sample.Name)
		}
		attempt, ok := latest[sample.SampleID]
		if !ok {
			return fmt.Errorf("no terminal attempt for %s", sample.Name)
		}
		got := classificationOf(attempt.ResultJSON)
		if got != want {
			return fmt.Errorf("sample %s classification=%s, expected %s",
				sample.Name, got, want)
		}
		if sample.Name == "04-clock-skew-missing.sample" {
			var evidence runner.Evidence
			if err := json.Unmarshal([]byte(attempt.ResultJSON), &evidence); err != nil {
				return err
			}
			if !contains(evidence.Findings, "CLOCK_SKEW") || len(evidence.MissingSegments) == 0 {
				return errors.New("clock+gap sample did not retain both findings")
			}
		}
	}
	return nil
}

func latestTerminalBySampleMap(attempts []model.Attempt) map[string]model.Attempt {
	out := make(map[string]model.Attempt)
	for _, attempt := range attempts {
		if isTerminalStatus(attempt.Status) {
			out[attempt.SampleID] = attempt
		}
	}
	return out
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

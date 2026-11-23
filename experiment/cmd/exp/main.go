// Command exp runs the replayable "YAML alias resource exhaustion"
// experiment: two parser snapshots (v1 vulnerable, v2 hardened) are
// run against a fixed corpus; every step is recorded in SQLite.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"yamlaliasexp/internal/corpus"
	"yamlaliasexp/internal/ledger"
	snapv2 "yamlaliasexp/internal/snap/v2"
)

type runner struct {
	led      *ledger.Ledger
	tmp      string
	evidence string
	fuzzDir  string
	self     string
	objects  []corpus.Object
	baseline map[string]parseOutcome // sha256 -> v2 outcome, for order check
}

func main() {
	worker := flag.Bool("worker", false, "run as parse worker (internal)")
	snap := flag.String("snap", "v2", "worker snapshot: v1|v2")
	memMB := flag.Int("mem-mb", 256, "worker RLIMIT_AS in MiB")
	evidence := flag.String("evidence", "artifacts/evidence", "evidence output dir")
	fuzzDir := flag.String("fuzz", "", "optional fuzz artifacts dir to copy into evidence")
	keep := flag.Bool("keep", false, "keep temporary work dir (skip cleanup)")
	flag.Parse()

	if *worker {
		if err := runWorker(*snap, *memMB); err != nil {
			fmt.Fprintln(os.Stderr, "worker:", err)
			os.Exit(2)
		}
		return
	}
	if err := runExperiment(*evidence, *fuzzDir, *keep); err != nil {
		log.Fatal(err)
	}
}

func runExperiment(evidence, fuzzDir string, keep bool) error {
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "yamlexp-")
	if err != nil {
		return err
	}
	runID := time.Now().UTC().Format("20060102T150405Z") + "-" + randHex(4)
	meta, _ := json.Marshal(map[string]any{
		"go_version": runtime.Version(),
		"snapshots":  []string{"v1(no-limits)", "v2(limits)"},
		"v2_limits":  snapv2.DefaultLimits(),
		"mem_mb":     map[string]int{"v1": 256, "v2": 512},
		"tmp_dir":    tmp,
	})
	led, err := ledger.Open(filepath.Join(tmp, "experiment.db"), runID, string(meta))
	if err != nil {
		return err
	}
	r := &runner{
		led: led, tmp: tmp, evidence: evidence, fuzzDir: fuzzDir,
		self: self, objects: corpus.Default(), baseline: map[string]parseOutcome{},
	}
	log.Printf("run_id=%s tmp=%s", runID, tmp)

	r.phaseInit()
	r.phaseParse("v1")
	r.phaseParse("v2")
	r.phaseOrder()
	r.phaseRepeat()
	if err := r.phaseEvidence(); err != nil {
		return err
	}
	if keep {
		log.Printf("keeping tmp dir: %s", tmp)
		return r.led.Close()
	}
	return r.phaseCleanup()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

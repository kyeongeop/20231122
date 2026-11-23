package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	"yamlaliasexp/internal/corpus"
	"yamlaliasexp/internal/ledger"
)

func memFor(snap string) int {
	if snap == "v1" {
		return 256
	}
	return 512
}

func (r *runner) step(phase, objID, snap string, obj *corpus.Object,
	state any, result string, detail any) {
	s := ledger.Step{Phase: phase, ObjectID: objID, Snapshot: snap, Result: result}
	if obj != nil {
		s.InputSHA256 = obj.SHA256()
		s.InputBytes = int64(len(obj.Content))
	}
	if b, err := json.Marshal(state); err == nil {
		s.State = string(b)
	}
	if b, err := json.Marshal(detail); err == nil {
		s.Detail = string(b)
	}
	id, err := r.led.AddStep(s)
	if err != nil {
		log.Fatalf("record step: %v", err)
	}
	log.Printf("step %d [%s] obj=%s snap=%s -> %s", id, phase, objID, snap, result)
}

// phaseInit registers every object and records its sniffed type.
func (r *runner) phaseInit() {
	dir := filepath.Join(r.tmp, "corpus")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	for i := range r.objects {
		obj := &r.objects[i]
		path := filepath.Join(dir, obj.Name)
		if err := os.WriteFile(path, obj.Content, 0o644); err != nil {
			log.Fatal(err)
		}
		if _, err := r.led.RegisterObject(obj.SHA256(), obj.Name, obj.Ext(),
			int64(len(obj.Content))); err != nil {
			log.Fatal(err)
		}
		r.step("init", obj.ID, "", obj, map[string]any{
			"path": path, "ext": obj.Ext(), "sniffed": corpus.Sniff(obj.Content),
			"order_index": i,
		}, "registered", nil)
	}
}

// processOne runs the parse pipeline for a single object. A panic
// (injected fault on empty objects) is recovered so the loop continues.
func (r *runner) processOne(obj *corpus.Object, snap string) (out parseOutcome) {
	defer func() {
		if rec := recover(); rec != nil {
			out = parseOutcome{Result: "panic_recovered", Error: fmt.Sprint(rec)}
		}
	}()
	if corpus.Sniff(obj.Content) == "empty" {
		panic("empty object: no decodable content") // injected fault
	}
	return r.runIsolated(snap, obj.Content, memFor(snap))
}

// phaseParse runs one snapshot over the whole corpus, continuing after
// exceptions. v2 outcomes become the baseline for the order check.
func (r *runner) phaseParse(snap string) {
	for i := range r.objects {
		obj := &r.objects[i]
		out := r.processOne(obj, snap)
		r.step("parse-"+snap, obj.ID, snap, obj, map[string]any{
			"mem_mb": memFor(snap), "timeout_s": 6, "order_index": i,
		}, out.Result, out)
		if snap == "v2" {
			r.baseline[obj.SHA256()] = out
		}
	}
}

// phaseOrder re-runs v2 over a shuffled corpus and verifies that each
// object produces the same result as in the baseline pass.
func (r *runner) phaseOrder() {
	seed := int64(len(r.led.RunID)) * 2654435761
	idx := rand.New(rand.NewSource(seed)).Perm(len(r.objects))
	divergent := 0
	for order, i := range idx {
		obj := &r.objects[i]
		out := r.processOne(obj, "v2")
		base, ok := r.baseline[obj.SHA256()]
		consistent := ok && base.Result == out.Result &&
			nodesOf(base) == nodesOf(out)
		if !consistent {
			divergent++
		}
		r.step("order-shuffled", obj.ID, "v2", obj, map[string]any{
			"shuffle_seed": seed, "shuffled_position": order, "orig_index": i,
		}, out.Result, map[string]any{
			"outcome": out, "baseline_result": base.Result, "consistent": consistent,
		})
	}
	verdict := "order_invariant"
	if divergent > 0 {
		verdict = "order_divergent"
	}
	r.step("order-verify", "", "v2", nil, map[string]any{
		"shuffle_seed": seed, "objects": len(idx),
	}, verdict, map[string]int{"divergent": divergent})
}

func nodesOf(o parseOutcome) int {
	if o.Metrics == nil {
		return -1
	}
	return o.Metrics.ExpandedNodes
}

// phaseRepeat resubmits known content (one under a new name) and
// verifies dedup detection plus identical parse outcomes.
func (r *runner) phaseRepeat() {
	repeats := []corpus.Object{
		{ID: "obj-benign-copy", Name: "benign-copy.yaml", Content: r.objects[0].Content},
		{ID: "obj-bomb", Name: "bomb.qzx", Content: r.objects[1].Content},
	}
	mismatches := 0
	for i := range repeats {
		obj := &repeats[i]
		seen, err := r.led.SeenBefore(obj.SHA256())
		if err != nil {
			log.Fatal(err)
		}
		count, err := r.led.RegisterObject(obj.SHA256(), obj.Name, obj.Ext(),
			int64(len(obj.Content)))
		if err != nil {
			log.Fatal(err)
		}
		out := r.runIsolated("v2", obj.Content, memFor("v2"))
		base := r.baseline[obj.SHA256()]
		same := base.Result == out.Result && nodesOf(base) == nodesOf(out)
		if !seen || !same {
			mismatches++
		}
		r.step("repeat-submit", obj.ID, "v2", obj, map[string]any{
			"seen_before": seen, "submit_count": count,
		}, "dedup_repeat", map[string]any{
			"outcome": out, "baseline_result": base.Result, "idempotent": same,
		})
	}
	verdict := "repeat_consistent"
	if mismatches > 0 {
		verdict = "repeat_inconsistent"
	}
	r.step("repeat-verify", "", "v2", nil, nil, verdict,
		map[string]int{"mismatches": mismatches})
}

// phaseCleanup records the cleanup step, snapshots the ledger into the
// evidence dir, then removes all temporary state.
func (r *runner) phaseCleanup() error {
	r.step("cleanup", "", "", nil, map[string]any{"tmp_dir": r.tmp},
		"temp_state_removed", nil)
	if err := r.snapshotDB(); err != nil {
		return err
	}
	if err := r.led.Close(); err != nil {
		return err
	}
	if err := os.RemoveAll(r.tmp); err != nil {
		return fmt.Errorf("cleanup: %w", err)
	}
	log.Printf("cleaned tmp dir %s", r.tmp)
	return nil
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proto-fuzz-exp/proto"
	"proto-fuzz-exp/store"
)

// verifyAll runs the three verification passes and logs outcomes.
func verifyAll(st *store.Store, runID int64, objects []object) {
	// 1. Replay: re-execute every object from its recorded inputs and
	//    compare each step (state, result) against the recorded log.
	for _, obj := range objects {
		rec := proto.Decode(obj.data)
		for _, version := range []int{1, 2} {
			logged, err := st.Steps(runID, obj.id, version)
			must(err)
			replayed := proto.Execute(version, rec)
			match := len(logged) == len(replayed)
			if match {
				for i := range logged {
					if logged[i].StateAfter != replayed[i].StateAfter ||
						logged[i].Result != replayed[i].Result ||
						logged[i].InputHex != replayed[i].InputHex {
						match = false
						break
					}
				}
			}
			outcome := "REPLAY_OK"
			if !match {
				outcome = "REPLAY_MISMATCH"
			}
			must(st.LogVerification(runID, "replay",
				fmt.Sprintf("%s/v%d", obj.id, version), outcome,
				fmt.Sprintf("steps=%d", len(logged))))
		}
	}
	fmt.Println("verify: replay determinism checked for all objects")

	// 2. Order change: swap AUTH and OPEN in obj-valid and compare the
	//    resulting step signature with the original order.
	reordered := []byte{
		1, 0,
		3, 0,
		2, 3, 'k', 'e', 'y',
		4, 2, 'h', 'i',
		5, 0,
	}
	for _, version := range []int{1, 2} {
		orig := proto.Signature(proto.Execute(version, proto.Decode(objects[0].data)))
		perm := proto.Signature(proto.Execute(version, proto.Decode(reordered)))
		outcome := "ORDER_SENSITIVE"
		if orig == perm {
			outcome = "ORDER_INSENSITIVE"
		}
		must(st.LogVerification(runID, "order_change",
			fmt.Sprintf("obj-valid/v%d", version), outcome,
			fmt.Sprintf("orig=%q permuted=%q", orig, perm)))
	}
	fmt.Println("verify: order-change sensitivity checked")

	// 3. Duplicate submission: execute obj-valid twice on fresh machines
	//    and confirm identical step signatures.
	for _, version := range []int{1, 2} {
		first := proto.Signature(proto.Execute(version, proto.Decode(objects[0].data)))
		second := proto.Signature(proto.Execute(version, proto.Decode(objects[0].data)))
		outcome := "DUPLICATE_DETERMINISTIC"
		if first != second {
			outcome = "DUPLICATE_DIVERGENT"
		}
		must(st.LogVerification(runID, "duplicate_submission",
			fmt.Sprintf("obj-valid/v%d", version), outcome,
			fmt.Sprintf("sig=%q", first)))
	}
	fmt.Println("verify: duplicate submission determinism checked")
}

// writeReport renders the key evidence from SQLite into report.md.
func writeReport(st *store.Store, runID int64, artifacts string, processed, exceptions int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Protocol State-Machine Fuzz Experiment — Run %d\n\n", runID)
	fmt.Fprintf(&b, "- objects processed: %d (exceptions recovered: %d)\n", processed, exceptions)
	fmt.Fprintf(&b, "- versions: v1 (buggy snapshot) vs v2 (fixed snapshot)\n\n")

	fmt.Fprintf(&b, "## Divergences (v1 vs v2)\n\n")
	divRows, err := st.Divergences(runID)
	if err != nil {
		return err
	}
	if len(divRows) == 0 {
		fmt.Fprintf(&b, "- none\n")
	}
	for _, d := range divRows {
		fmt.Fprintf(&b, "- `%s`: v1 final=`%s` vs v2 final=`%s`\n", d[0], d[1], d[2])
	}

	fmt.Fprintf(&b, "\n## Verifications\n\n")
	verRows, err := st.Verifications(runID)
	if err != nil {
		return err
	}
	for _, v := range verRows {
		fmt.Fprintf(&b, "- [%s] `%s` -> **%s** (%s)\n", v[0], v[1], v[2], v[3])
	}

	fmt.Fprintf(&b, "\n## Control Object (truncated record)\n\n")
	ctl, err := st.Steps(runID, "obj-truncated-control", 2)
	if err != nil {
		return err
	}
	for _, s := range ctl {
		fmt.Fprintf(&b, "- seq=%d input=`%s` %s->%s result=`%s`\n",
			s.Seq, s.InputHex, s.StateBefore, s.StateAfter, s.Result)
	}

	return os.WriteFile(filepath.Join(artifacts, "report.md"), []byte(b.String()), 0o644)
}

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"proto-fuzz-exp/proto"
	"proto-fuzz-exp/store"
)

// object is one named test object (a raw wire-format byte stream).
type object struct {
	id   string
	data []byte
}

func seedObjects() []object {
	return []object{
		{id: "obj-valid", data: []byte{
			1, 0, // HELLO
			2, 3, 'k', 'e', 'y', // AUTH key
			3, 0, // OPEN
			4, 2, 'h', 'i', // SEND "hi"
			5, 0, // CLOSE
		}},
		// Control object: trailing record is truncated (SEND len=5, 1 byte present).
		{id: "obj-truncated-control", data: []byte{
			1, 0,
			2, 1, 'k',
			4, 5, 'A',
		}},
		// SEND before OPEN: triggers the v1 panic (exception path).
		{id: "obj-send-first", data: []byte{
			4, 1, 'x',
		}},
		// Duplicate submissions within one record.
		{id: "obj-duplicates", data: []byte{
			1, 0, 1, 0,
			2, 1, 'k', 2, 1, 'k',
			3, 0,
			5, 0, 5, 0,
		}},
		// CLOSE from IDLE: v1/v2 behavioural divergence without panic.
		{id: "obj-close-early", data: []byte{
			5, 0,
		}},
	}
}

func loadCrashObjects(dir string) []object {
	matches, _ := filepath.Glob(filepath.Join(dir, "crash-*"))
	sort.Strings(matches)
	if len(matches) > 64 {
		matches = matches[:64]
	}
	var objs []object
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		objs = append(objs, object{id: "fuzz-" + filepath.Base(m), data: b})
	}
	return objs
}

func main() {
	artifacts := flag.String("artifacts", "../artifacts", "evidence output directory")
	flag.Parse()

	crashDir := filepath.Join(*artifacts, "crashes")
	tmpDir, err := os.MkdirTemp("", "fuzzexp-")
	must(err)
	defer func() {
		os.RemoveAll(tmpDir)
		fmt.Println("cleanup: removed temp dir", tmpDir)
	}()

	st, err := store.Open(filepath.Join(*artifacts, "evidence.sqlite"))
	must(err)
	defer st.Close()

	runID, err := st.BeginRun("protocol state machine differential fuzz experiment (v1 vs v2)")
	must(err)
	fmt.Printf("run id: %d\n", runID)

	objects := append(seedObjects(), loadCrashObjects(crashDir)...)
	fmt.Printf("objects: %d (incl. %d fuzz artifacts)\n",
		len(objects), len(objects)-len(seedObjects()))

	// ---- Record phase: log every step (input, state, result) per object.
	exceptions := 0
	processed := 0
	for _, obj := range objects {
		rec := proto.Decode(obj.data)
		for _, version := range []int{1, 2} {
			steps := proto.Execute(version, rec)
			for _, s := range steps {
				must(st.LogStep(runID, obj.id, version, s.Seq,
					s.InputHex, s.StateBefore, s.StateAfter, s.Result))
			}
			for _, s := range steps {
				if isException(s.Result) {
					exceptions++
				}
			}
		}
		processed++ // exceptions are recovered inside Execute; keep going
	}
	fmt.Printf("record phase: processed=%d exceptions=%d\n", processed, exceptions)

	// ---- Verify phase: replay, order change, duplicate submission.
	verifyAll(st, runID, objects)

	// ---- Report (key evidence).
	must(writeReport(st, runID, *artifacts, processed, exceptions))
	fmt.Println("evidence: " + filepath.Join(*artifacts, "evidence.sqlite"))
	fmt.Println("report:   " + filepath.Join(*artifacts, "report.md"))
}

func isException(result string) bool {
	return len(result) >= 10 && result[:10] == "EXCEPTION:"
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

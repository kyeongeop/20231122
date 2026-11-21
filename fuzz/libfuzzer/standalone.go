//go:build !libfuzzer

// Without the libfuzzer tag the package still builds as a normal command that
// runs the harness over files passed on the command line (or stdin), so the
// cgo-free code path stays covered by ordinary CI.
package main

import (
	"fmt"
	"os"

	"lfireview/internal/fuzzshim"
)

func main() {
	if len(os.Args) < 2 {
		data, err := os.ReadFile("/dev/stdin")
		if err != nil {
			fmt.Fprintln(os.Stderr, "usage: libfuzzer <corpus-file> [...]")
			os.Exit(2)
		}
		os.Exit(fuzzshim.Entry(data))
	}
	for _, path := range os.Args[1:] {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			continue
		}
		fuzzshim.Entry(data)
	}
}

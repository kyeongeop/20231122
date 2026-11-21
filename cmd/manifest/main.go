// Command manifest writes a SHA-256 manifest of every preserved input so the
// "unmodified original material" claim can be verified independently.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func main() {
	base := flag.String("base", ".", "workspace root")
	flag.Parse()

	dirs := []string{"evidence/corpus", "evidence/original"}
	var lines []string
	for _, dir := range dirs {
		root := filepath.Join(*base, dir)
		entries, err := os.ReadDir(root)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(root, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			sum := sha256.Sum256(data)
			rel, _ := filepath.Rel(*base, path)
			lines = append(lines, fmt.Sprintf("%s  %s  %d bytes",
				hex.EncodeToString(sum[:]), rel, len(data)))
		}
	}
	sort.Strings(lines)

	out := filepath.Join(*base, "evidence", "reports", "SHA256SUMS")
	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Fprintf(f, "# manifest generated %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, line := range lines {
		fmt.Fprintln(f, line)
	}
	fmt.Printf("wrote %d entries -> %s\n", len(lines), out)
}

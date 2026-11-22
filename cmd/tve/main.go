// Command tve runs the pausable template-variable-escaping pipeline.
//
// Subcommands:
//
//	gen-material  generate + preserve the original material
//	run           create a job and process it (may pause / exhaust)
//	resume        resume a job from its latest checkpoint
//	verify       acceptance: compare against reference, check evidence
//	events        dump key evidence (timestamps + raw offsets)
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"tve/internal/material"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-material":
		err = cmdGenMaterial()
	case "run":
		err = cmdRun(os.Args[2:])
	case "resume":
		err = cmdResume(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "events":
		err = cmdEvents(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  tve gen-material [-dir artifacts] [-seed 7]
  tve run [-db tve.db] [-dir artifacts] [-seed N] [-repeat N] [-template-pad N]
          [-value-len N] [-batch N] [-max-value N] [-max-output N]
          [-pause-after N] [-budget N]
  tve resume [-db tve.db] [-dir artifacts] -job ID
  tve verify [-db tve.db] [-dir artifacts] -job ID
  tve events [-db tve.db] -job ID
`)
}

const (
	defDB  = "tve.db"
	defDir = "artifacts"
)

func cmdGenMaterial() error {
	fs := newFlagSet("gen-material")
	dir := fs.String("dir", defDir, "artifact directory")
	seed := fs.Int64("seed", 7, "deterministic seed")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	mat := material.Generate(*seed)
	sum, err := material.Preserve(*dir, mat)
	if err != nil {
		return err
	}
	fmt.Printf("material preserved: %s sha256=%s bytes=%d\n",
		filepath.Join(*dir, "material.bin"), sum, len(mat))
	return nil
}

func loadMaterial(dir string, seed int64) ([]byte, string, error) {
	path := filepath.Join(dir, "material.bin")
	data, err := os.ReadFile(path)
	if err == nil {
		return data, material.SHA256(data), nil
	}
	// No preserved copy yet: generate and preserve it now.
	mat := material.Generate(seed)
	sum, err := material.Preserve(dir, mat)
	if err != nil {
		return nil, "", err
	}
	return mat, sum, nil
}

package main

import (
	"os"
	"path/filepath"
)

// seedLibFuzzerCorpus copies seed inputs into the persistent libFuzzer
// corpus directory, skipping names already present so repeated campaigns
// accumulate rather than overwrite.
func seedLibFuzzerCorpus(seedDir, corpusDir string) error {
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(seedDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dst := filepath.Join(corpusDir, "seed_"+e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(seedDir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

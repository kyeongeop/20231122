package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"krfix/internal/material"
)

func runBuild(layout material.Layout, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := projectRoot()
	if err != nil {
		return err
	}
	script := filepath.Join(root, "scripts", "build.sh")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("build script not found: %w", err)
	}
	cmd := exec.Command("bash", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CLANG="+resolveClang(),
		"OUT="+layout.BuildDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("libFuzzer harness build failed: %w", err)
	}
	fmt.Println("krfix: harnesses ready in", layout.BuildDir)
	return nil
}

package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"idorfix/internal/domain"
)

// storeLike is the subset of store.Store used by command handlers.
type storeLike interface {
	SamplePayload(ctx context.Context, sampleID string) (string, error)
	ListRuns(ctx context.Context, sampleID string) ([]domain.Run, error)
}

func cmdRecover(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	workspace, err := openStore(ctx, flags["db"])
	if err != nil {
		return err
	}
	defer workspace.Close()

	recovered, err := workspace.RecoverInterrupted(ctx, processAlive)
	if err != nil {
		return err
	}
	if len(recovered) == 0 {
		fmt.Println("no interrupted runs found")
		return nil
	}
	for _, run := range recovered {
		fmt.Printf("marked INTERRUPTED run=%s sample=%s attempt=%d\n",
			run.RunID, run.SampleID, run.Attempt)
	}
	fmt.Println("re-enter with: idorfix run --sample <SAMPLE_ID>")
	return nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 only checks liveness; it never affects the target process.
	return process.Signal(syscall.Signal(0)) == nil
}

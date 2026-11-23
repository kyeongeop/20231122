package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"idorfix/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "idorfix:", err)
		os.Exit(1)
	}
}

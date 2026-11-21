package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"auditfix/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := cli.New().Run(ctx, os.Args[1:])
	if code != 0 && ctx.Err() != nil {
		code = 130
	}
	os.Exit(code)
}

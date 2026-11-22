package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"webhookprovenance/internal/inspect"
	"webhookprovenance/internal/web"
)

func main() {
	addr := flag.String("addr", envOr("ADDR", "127.0.0.1:8787"), "HTTP listen address")
	dbPath := flag.String("db", envOr("DB_PATH", "data/inspect.db"), "SQLite database path")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}

	store, err := inspect.OpenStore(*dbPath)
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := store.Bootstrap(context.Background()); err != nil {
		logger.Error("bootstrap evidence store", "error", err)
		os.Exit(1)
	}

	srv := web.NewServer(store, logger)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("source inspection ready", "url", "http://"+*addr, "db", *dbPath)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	if removed, err := store.CleanupTemporary(shutdownCtx); err != nil {
		logger.Warn("cleanup temporary state", "error", err)
	} else {
		logger.Info("temporary state cleaned", "entries", removed)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

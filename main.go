package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crashprovenance/internal/httpapi"
	"crashprovenance/internal/store"
)

//go:embed web/*
var webAssets embed.FS

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "evidence/forensics.db", "SQLite evidence database")
	flag.Parse()

	logger := httpapi.MainLogger()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		logger.Error("open evidence store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		logger.Error("load web assets", "error", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	httpapi.New(st, logger).Register(mux)
	httpapi.ServeStatic(mux, http.FS(webRoot))

	server := &http.Server{
		Addr:              *addr,
		Handler:           httpapi.Secure(httpapi.LogRequests(logger, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("crash provenance listening", "addr", *addr, "db", *dbPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("serve", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", "error", err)
	}
	fmt.Println("evidence store closed")
}

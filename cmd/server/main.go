package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"tracecheck/internal/runner"
	"tracecheck/internal/server"
	"tracecheck/internal/store"
)

func main() {
	dbPath := envOr("TRACE_DB", "data/tracecheck.db")
	addr := envOr("ADDR", ":8080")

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	svc := runner.New(st)
	srv, err := server.New(st, svc)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("tracecheck listening on http://localhost%s (db=%s)", addr, dbPath)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

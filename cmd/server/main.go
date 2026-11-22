package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crossdomain-audit/internal/audit"
	"crossdomain-audit/web"
)

func main() {
	port := envOr("PORT", "8080")
	dbPath := envOr("DB_PATH", filepath.Join("data", "audit.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Fatal(err)
	}
	store, err := audit.Open(dbPath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           routes(store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("cross-domain audit listening on http://localhost:%s", port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func routes(store *audit.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "storage": "sqlite"})
	})
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		stats, err := store.Stats(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})
	mux.HandleFunc("GET /api/audits", func(w http.ResponseWriter, r *http.Request) {
		items, err := store.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /api/audits/{id}", func(w http.ResponseWriter, r *http.Request) {
		item, err := store.Get(r.Context(), r.PathValue("id"))
		if errors.Is(err, audit.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	})

	assets, err := fs.Sub(web.Files, ".")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /styles.css", http.FileServer(http.FS(assets)))
	mux.Handle("GET /app.js", http.FileServer(http.FS(assets)))
	mux.Handle("GET /favicon.svg", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page, err := fs.ReadFile(assets, "index.html")
		if err != nil {
			http.Error(w, "page unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	})
	return securityHeaders(requestLog(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": fmt.Sprintf("%v", err)})
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

type server struct {
	store *Store
}

func main() {
	dbPath := envOr("DB_PATH", "data/pathscope.db")
	caseID := envOr("CASE_ID", "PN-231122-0417")
	addr := envOr("ADDR", ":8080")

	store, err := openStore(dbPath, caseID)
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	defer store.db.Close()

	app := &server{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", app.handleHealth)
	mux.HandleFunc("GET /api/case", app.handleCase)
	mux.HandleFunc("POST /api/replay", app.handleReplay)
	mux.HandleFunc("POST /api/reviews", app.handleReview)
	mux.HandleFunc("POST /api/followups/{id}/status", app.handleFollowupStatus)
	mux.HandleFunc("GET /api/export", app.handleExport)

	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticRoot)))

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           withCommonHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("PathScope listening on %s (db=%s, case=%s)", addr, dbPath, caseID)
	log.Fatal(httpServer.ListenAndServe())
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	var now string
	if err := s.store.db.QueryRow(`SELECT datetime('now')`).Scan(&now); err != nil {
		writeError(w, http.StatusServiceUnavailable, "SQLite health check failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "sqlite": "ready", "sqliteTimeUTC": now,
		"caseId": s.store.caseID, "time": nowISO(),
	})
}

func (s *server) handleCase(w http.ResponseWriter, _ *http.Request) {
	detail, err := s.store.loadCaseDetail()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *server) handleReplay(w http.ResponseWriter, r *http.Request) {
	if !acceptsJSON(r) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	result, err := s.store.replayRecovered()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail, err := s.store.loadCaseDetail()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"result": result, "case": detail})
}

func (s *server) handleReview(w http.ResponseWriter, r *http.Request) {
	if !acceptsJSON(r) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var payload struct {
		Decision string `json:"decision"`
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
	}
	if err := decodeJSON(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	review, err := s.store.addReview(payload.Decision, payload.Reviewer, payload.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	detail, err := s.store.loadCaseDetail()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"review": review, "case": detail})
}

func (s *server) handleFollowupStatus(w http.ResponseWriter, r *http.Request) {
	if !acceptsJSON(r) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := s.store.setFollowupStatus(r.PathValue("id"), payload.Status)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "follow-up not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"followup": item})
}

func (s *server) handleExport(w http.ResponseWriter, _ *http.Request) {
	detail, err := s.store.loadCaseDetail()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	payload, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", s.store.caseID+"-evidence-pack.json"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(payload, '\n'))
}

func acceptsJSON(r *http.Request) bool {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(contentType, "application/json")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

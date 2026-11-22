package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"webhookprovenance/internal/inspect"
)

//go:embed ui/*
var assets embed.FS

type Server struct {
	store  *inspect.Store
	logger *slog.Logger
}

func NewServer(store *inspect.Store, logger *slog.Logger) *Server {
	return &Server{store: store, logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/case", s.caseJSON)
	mux.HandleFunc("GET /api/export", s.exportJSON)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /api/recheck", s.recheckAll)
	mux.HandleFunc("POST /api/objects/{id}/verify", s.recheckOne)
	mux.HandleFunc("POST /api/cleanup", s.cleanup)

	ui, err := fs.Sub(assets, "ui")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(ui))))
	return s.middleware(mux)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) caseJSON(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.store.Case(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) recheckOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, errors.New("object id required"))
		return
	}
	obj, err := s.store.RunObject(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": obj, "message": "单个对象复验完成；证据已替换为本次结果。",
	})
}

func (s *Server) recheckAll(w http.ResponseWriter, r *http.Request) {
	result, err := s.store.RunAll(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) cleanup(w http.ResponseWriter, r *http.Request) {
	removed, err := s.store.CleanupTemporary(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed": removed,
		"message": "临时复验状态已清理；SQLite 中的原始输入与结论证据保持不变。",
	})
}

func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.store.Case(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	payload := map[string]any{
		"format":     "webhook-provenance-evidence/v1",
		"exportedAt": time.Now().UTC().Format(time.RFC3339),
		"case":       snapshot,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="WH-2026-1122-evidence.json"`)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "store": "sqlite"})
}

func (s *Server) writeError(w http.ResponseWriter, status int, err error) {
	s.logger.Error("request failed", "status", status, "error", err)
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			s.logger.Info("request", "method", r.Method, "path", r.URL.Path,
				"duration", time.Since(start).Round(time.Millisecond))
		}
	})
}

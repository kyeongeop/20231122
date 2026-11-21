package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"crashprovenance/internal/store"
)

type API struct {
	store *store.Store
	log   *slog.Logger
}

func New(st *store.Store, logger *slog.Logger) *API {
	return &API{store: st, log: logger}
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("GET /api/report", a.report)
	mux.HandleFunc("POST /api/replay", a.replay)
	mux.HandleFunc("POST /api/manual-review", a.manualReview)
	mux.HandleFunc("GET /api/evidence/{id}", a.evidence)
	mux.HandleFunc("GET /api/export", a.export)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) report(w http.ResponseWriter, r *http.Request) {
	sampleID := sampleFrom(r)
	report, err := a.store.GetReport(r.Context(), sampleID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type reviewRequest struct {
	SampleID string `json:"sample_id"`
	CheckID  string `json:"check_id"`
	Status   string `json:"status"`
	Reviewer string `json:"reviewer"`
	Note     string `json:"note"`
}

func (a *API) manualReview(w http.ResponseWriter, r *http.Request) {
	var req reviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	if req.SampleID == "" {
		req.SampleID = store.DefaultSampleID
	}
	report, err := a.store.ReviewManual(r.Context(), req.SampleID, req.CheckID, req.Status, req.Reviewer, req.Note)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type replayRequest struct {
	SampleID string `json:"sample_id"`
}

func (a *API) replay(w http.ResponseWriter, r *http.Request) {
	var req replayRequest
	if r.ContentLength > 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
	}
	if req.SampleID == "" {
		req.SampleID = store.DefaultSampleID
	}
	report, err := a.store.RunReplay(r.Context(), req.SampleID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *API) evidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	content, label, err := a.store.EvidenceContent(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	filename := safeFilename(label)
	if filename == "" {
		filename = id + ".bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *API) export(w http.ResponseWriter, r *http.Request) {
	pkg, err := a.store.Export(r.Context(), sampleFrom(r))
	if err != nil {
		a.fail(w, err)
		return
	}
	payload, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		a.fail(w, err)
		return
	}
	name := fmt.Sprintf("%s-evidence-%s.json", pkg.Report.Sample.ID, time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (a *API) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidReview):
		writeError(w, http.StatusBadRequest, err.Error())
	case a.store.IsNoRows(err):
		writeError(w, http.StatusNotFound, "没有找到对应记录")
	default:
		a.log.Error("request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "证据库操作失败，请检查服务日志")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func sampleFrom(r *http.Request) string {
	if value := strings.TrimSpace(r.URL.Query().Get("sample")); value != "" {
		return value
	}
	return store.DefaultSampleID
}

func safeFilename(label string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", "\"", "", "\n", "", "\r", "")
	return strings.TrimSpace(replacer.Replace(label))
}

func ServeStatic(mux *http.ServeMux, fs http.FileSystem) {
	fileServer := http.FileServer(fs)
	mux.Handle("/", fileServer)
}

func LogRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("http", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start).String())
	})
}

func Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func MainLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

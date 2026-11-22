package server

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"tracecheck/internal/detector"
	"tracecheck/internal/model"
	"tracecheck/internal/runner"
	"tracecheck/internal/store"
	"tracecheck/web"
)

type Server struct {
	store  *store.Store
	runner *runner.Service
	tmpl   *template.Template
}

type PageData struct {
	Check            *model.Check
	Active           *model.Attempt
	Cancellations    []model.Attempt
	Failure          *model.Attempt
	RawLines         []CodeLine
	NormalizedLines  []CodeLine
	FindingCount     int
	RiskCount        int
	BoundaryCount    int
	RetainedCount    int
	CompletedCount   int
	RuleSummary      string
	RuleDetail       string
	PrimaryEvidence  string
	FuzzEvidence     string
	BoundaryEvidence string
	Running          bool
}

type CodeLine struct {
	Number     int
	Segments   []Segment
	Hit        bool
	Ambiguous  bool
	EvidenceID string
	Marker     string
}

type Segment struct {
	Text  string
	Class string
}

func New(s *store.Store, r *runner.Service) (*Server, error) {
	funcs := template.FuncMap{
		"fmtTime":     formatTime,
		"fmtDateTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"shortTime":   func(t time.Time) string { return t.Format("15:04:05") },
		"shortSHA":    shortSHA,
		"pct":         func(v float64) string { return fmt.Sprintf("%.0f", v*100) },
		"duration":    duration,
		"statusLabel": statusLabel,
		"statusClass": statusClass,
		"severity":    severityLabel,
		"initials":    initials,
		"add":         func(a, b int) int { return a + b },
		"attemptURL":  func(id, attempt string) string { return "/checks/" + id + "#attempt-" + attempt },
	}
	tmpl, err := template.New("root").Funcs(funcs).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{store: s, runner: r, tmpl: tmpl}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /checks/{id}", s.handleCheck)
	mux.HandleFunc("GET /checks/{id}/export", s.handleExport)
	mux.HandleFunc("GET /api/checks/{id}/status", s.handleStatus)
	mux.HandleFunc("POST /api/checks", s.handleCreate)
	mux.HandleFunc("POST /api/checks/{id}/confirm", s.handleConfirm)
	mux.HandleFunc("POST /api/checks/{id}/attempts/{attemptID}/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/evidence/{id}", s.handleEvidence)
	mux.HandleFunc("GET /api/evidence/{id}/meta", s.handleEvidenceMeta)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	staticFS, err := fs.Sub(web.FS, "static")
	if err == nil {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	checks, err := s.store.ListChecks(r.Context())
	if err != nil || len(checks) == 0 {
		http.Error(w, "no checks", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/checks/"+checks[0].ID, http.StatusFound)
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	check, err := s.store.GetCheck(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := buildPage(check)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "page.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func buildPage(c *model.Check) PageData {
	data := PageData{
		Check: c, Active: c.SelectedAttempt,
		RawLines:        codeLines(c.RawInput, false),
		NormalizedLines: codeLines(c.Normalized, true),
		Running:         c.Status == "running",
	}
	for i := range c.Attempts {
		a := c.Attempts[i]
		switch a.Status {
		case "cancelled":
			data.Cancellations = append(data.Cancellations, a)
		case "failed":
			data.Failure = &c.Attempts[i]
		case "completed":
			data.CompletedCount++
		}
	}
	for _, f := range c.Findings {
		data.FindingCount++
		if f.Severity == "high" || f.Severity == "medium" {
			data.RiskCount++
		}
		if f.Severity == "unknown" {
			data.BoundaryCount++
		}
	}
	for _, e := range c.Evidence {
		if e.Retained {
			data.RetainedCount++
		}
		switch e.Kind {
		case "derived":
			if data.PrimaryEvidence == "" {
				data.PrimaryEvidence = e.ID
			}
		case "fuzzer-artifact":
			data.FuzzEvidence = e.ID
		case "boundary":
			data.BoundaryEvidence = e.ID
		}
	}
	if data.PrimaryEvidence == "" && len(c.Evidence) > 0 {
		data.PrimaryEvidence = c.Evidence[0].ID
	}
	if data.BoundaryEvidence == "" && data.PrimaryEvidence != "" {
		data.BoundaryEvidence = data.PrimaryEvidence
	}
	if data.FuzzEvidence == "" && data.PrimaryEvidence != "" {
		data.FuzzEvidence = data.PrimaryEvidence
	}
	var rules []string
	seen := map[string]bool{}
	for _, f := range c.Findings {
		if f.Severity == "unknown" {
			continue
		}
		if !seen[f.Rule] {
			rules = append(rules, f.Rule)
			seen[f.Rule] = true
		}
	}
	if len(rules) > 0 {
		data.RuleSummary = strings.Join(rules, " + ")
		data.RuleDetail = fmt.Sprintf("%d 项规则命中", len(rules))
	} else if c.AmbiguousRule != "" {
		data.RuleSummary = c.AmbiguousRule
		data.RuleDetail = "仅边界待判断"
	} else if c.Status == "running" {
		data.RuleSummary = "分析中"
		data.RuleDetail = "等待规则输出"
	} else {
		data.RuleSummary = "未形成规则结论"
		data.RuleDetail = "处理未完成"
	}
	return data
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.CheckStatus(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title     string `json:"title"`
		Source    string `json:"source"`
		InputName string `json:"input_name"`
		Input     string `json:"input"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无法读取输入"})
		return
	}
	if strings.TrimSpace(body.Input) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入待检查日志"})
		return
	}
	if body.Title == "" {
		body.Title = "日志注入 · 来源检查"
	}
	if body.Source == "" {
		body.Source = "manual / workspace"
	}
	if body.InputName == "" {
		body.InputName = "pasted-log-" + time.Now().Format("150405") + ".log"
	}
	checkID, attemptID, err := s.store.CreateCheck(r.Context(), body.Title, body.Source, body.InputName, []byte(body.Input))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.runner.Start(checkID, attemptID, []byte(body.Input))
	writeJSON(w, http.StatusCreated, map[string]string{"check_id": checkID, "attempt_id": attemptID})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Verdict  string `json:"verdict"`
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效请求"})
		return
	}
	labels := map[string]string{
		"confirmed": "已确认注入",
		"benign":    "确认无害",
		"review":    "需进一步复核",
	}
	label, ok := labels[body.Verdict]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请选择人工结论"})
		return
	}
	if strings.TrimSpace(body.Reviewer) == "" || strings.TrimSpace(body.Note) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "复核人和判断依据不能为空"})
		return
	}
	if err := s.store.ConfirmCheck(r.Context(), r.PathValue("id"), body.Verdict, label, body.Reviewer, body.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"label": label})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body)
	if body.Actor == "" {
		body.Actor = "当前操作员"
	}
	if body.Reason == "" {
		body.Reason = "操作员中途取消；已完成步骤与原始输入已保留。"
	}
	checkID := r.PathValue("id")
	attemptID := r.PathValue("attemptID")
	s.runner.Stop(attemptID)
	if err := s.store.CancelAttempt(r.Context(), checkID, attemptID, body.Actor, body.Reason); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled", "attempt_id": attemptID})
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.EvidenceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.bin"`, e.ID, sanitizeName(e.Kind)))
	w.Header().Set("X-Evidence-SHA256", e.SHA256)
	_, _ = io.WriteString(w, e.Content)
}

func (s *Server) handleEvidenceMeta(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.EvidenceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCheck(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-evidence.zip"`, c.ID))
	zw := zip.NewWriter(w)
	defer zw.Close()
	writeZip := func(name string, data []byte) {
		f, err := zw.Create(path.Clean(name))
		if err == nil {
			_, _ = f.Write(data)
		}
	}
	manifest, _ := json.MarshalIndent(c, "", "  ")
	writeZip("manifest.json", manifest)
	writeZip("raw-input.log", []byte(c.RawInput))
	steps, _ := json.MarshalIndent(c.Attempts, "", "  ")
	writeZip("attempts-and-steps.json", steps)
	evidence, _ := json.MarshalIndent(c.Evidence, "", "  ")
	writeZip("evidence.json", evidence)
	audits, _ := json.MarshalIndent(c.Audits, "", "  ")
	writeZip("audit-trail.json", audits)
}

func formatTime(t time.Time) string {
	now := time.Now()
	if t.Format("2006-01-02") == now.Format("2006-01-02") {
		return "今天 " + t.Format("15:04")
	}
	return t.Format("01-02 15:04")
}

func shortSHA(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:8] + "…" + v[len(v)-4:]
}

func duration(a model.Attempt) string {
	if a.EndedAt == nil {
		return "进行中"
	}
	d := a.EndedAt.Sub(a.StartedAt)
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func statusLabel(status string) string {
	return map[string]string{
		"completed": "已完成", "running": "进行中", "cancelled": "中途取消",
		"failed": "失败", "pending": "等待", "skipped": "未执行",
	}[status]
}

func statusClass(status string) string {
	return map[string]string{
		"completed": "ok", "running": "run", "cancelled": "warn",
		"failed": "bad", "pending": "idle", "skipped": "idle",
	}[status]
}

func severityLabel(v string) string {
	return map[string]string{"high": "高风险", "medium": "中风险", "low": "低风险", "unknown": "无法判断"}[v]
}

func initials(name string) string {
	r := []rune(strings.TrimSpace(name))
	if len(r) == 0 {
		return "?"
	}
	if len(r) >= 2 {
		return string(r[:2])
	}
	return string(r[0])
}

func codeLines(raw string, normalized bool) []CodeLine {
	src := raw
	if normalized {
		src = detector.Normalize(raw)
	}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out []CodeLine
	for i, line := range lines {
		cl := CodeLine{Number: i + 1}
		switch {
		case strings.Contains(line, "%0d%0a") || strings.Contains(line, "%0D%0A"):
			cl = splitHit(cl, line, "%0d%0a", "E-103", "CRLF")
			if !strings.Contains(strings.ToLower(line), "%0d%0a") {
				cl = splitHit(cl, line, "%0D%0A", "E-103", "CRLF")
			}
		case strings.Contains(line, "\u2028") || strings.Contains(line, "\u2029"):
			sep := "\u2028"
			if strings.Contains(line, "\u2029") {
				sep = "\u2029"
			}
			cl = splitHit(cl, line, sep, "E-104", "U+2028")
			cl.Ambiguous = true
		case normalized && strings.Contains(strings.ToLower(line), "info audit"):
			cl.Hit = true
			cl.EvidenceID = "E-103"
			cl.Marker = "伪造行"
			cl.Segments = []Segment{{Text: line, Class: "injected"}}
		default:
			cl.Segments = []Segment{{Text: line}}
		}
		out = append(out, cl)
	}
	return out
}

func splitHit(cl CodeLine, line, token, evidenceID, marker string) CodeLine {
	parts := strings.Split(line, token)
	cl.Hit = true
	cl.EvidenceID = evidenceID
	cl.Marker = marker
	for i, part := range parts {
		cl.Segments = append(cl.Segments, Segment{Text: part})
		if i < len(parts)-1 {
			cl.Segments = append(cl.Segments, Segment{Text: token, Class: "token-hit"})
		}
	}
	return cl
}

func sanitizeName(v string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

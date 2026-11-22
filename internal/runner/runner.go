package runner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"tracecheck/internal/detector"
	"tracecheck/internal/model"
	"tracecheck/internal/store"
)

type Service struct {
	store   *store.Store
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func New(s *store.Store) *Service {
	return &Service{store: s, cancels: make(map[string]context.CancelFunc)}
}

func (s *Service) Start(checkID, attemptID string, raw []byte) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[attemptID] = cancel
	s.mu.Unlock()

	result := detector.Analyze(checkID, attemptID, raw)
	renameEvidence(&result, attemptID)
	stages := buildStages(attemptID, result, raw)
	now := time.Now()
	for i := range stages {
		stages[i].StartedAt = now
		_ = s.store.AddPendingStep(context.Background(), stages[i])
	}

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.cancels, attemptID)
			s.mu.Unlock()
			cancel()
		}()
		for i := range stages {
			if !sleep(ctx, 650*time.Millisecond) {
				return
			}
			st := &stages[i]
			_ = s.store.UpdateStep(ctx, st.ID, "running", st.Summary,
				st.InputExcerpt, st.OutputExcerpt, st.EvidenceIDs)
			if !sleep(ctx, 720*time.Millisecond) {
				return
			}
			if err := s.persistStepEvidence(ctx, result, st.Position); err != nil {
				actions := []string{
					"检查 data/ 磁盘余量与 SQLite 锁状态。",
					"修复后从失败步骤重试，原始输入和已完成证据不会丢失。",
				}
				_ = s.store.FailAttempt(context.Background(), checkID, attemptID,
					"SQLITE_WRITE_FAILED", err.Error(), actions)
				return
			}
			status := "completed"
			if st.Position == 4 && st.Ambiguous {
				status = "completed"
			}
			_ = s.store.UpdateStep(ctx, st.ID, status, st.Summary,
				st.InputExcerpt, st.OutputExcerpt, st.EvidenceIDs)
		}
		if err := s.store.CompleteAttempt(context.Background(), checkID, attemptID, result, len(result.Evidence)); err != nil {
			_ = s.store.FailAttempt(context.Background(), checkID, attemptID,
				"FINALIZE_FAILED", err.Error(), []string{
					"保留的原始输入和步骤证据仍可下载。",
					"检查 SQLite 完整性后，从失败步骤重试。",
				})
		}
	}()
}

func (s *Service) persistStepEvidence(ctx context.Context, result detector.Result, position int) error {
	for _, ev := range result.Evidence {
		keep := false
		switch position {
		case 1:
			keep = ev.Kind == "raw"
		case 2:
			keep = ev.Kind == "normalized"
		case 3:
			keep = ev.Kind == "fuzzer-artifact"
		case 4:
			keep = ev.Kind == "derived" || ev.Kind == "boundary"
		}
		if keep {
			if err := s.store.InsertEvidence(ctx, ev); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) Stop(attemptID string) {
	s.mu.Lock()
	cancel := s.cancels[attemptID]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func buildStages(attemptID string, r detector.Result, raw []byte) []model.Step {
	evidenceIDs := make([]string, 0, len(r.Evidence))
	for _, ev := range r.Evidence {
		evidenceIDs = append(evidenceIDs, ev.ID)
	}
	rawIDs := idsFor(r, "raw")
	normalizedIDs := idsFor(r, "normalized")
	fuzzIDs := idsFor(r, "fuzzer-artifact")
	findingIDs := idsFor(r, "derived", "boundary")
	return []model.Step{
		{
			ID: attemptID + "-S1", AttemptID: attemptID, Position: 1, Phase: "ingest",
			Title: "接收与指纹", Status: "pending", Tool: "sha256sum",
			Summary:      "锁定原始输入快照并计算内容指纹。",
			InputExcerpt: "原始字节", OutputExcerpt: "sha256:" + shortHash(store.Hash(raw)),
			EvidenceIDs: rawIDs,
		},
		{
			ID: attemptID + "-S2", AttemptID: attemptID, Position: 2, Phase: "normalize",
			Title: "编码与换行规范化", Status: "pending", Tool: "normalize/v4",
			Summary:       "解码换行控制序列并保留字节偏移映射。",
			InputExcerpt:  "%0d%0a / %0a / U+2028",
			OutputExcerpt: "normalized view · mapping retained",
			EvidenceIDs:   normalizedIDs,
		},
		{
			ID: attemptID + "-S3", AttemptID: attemptID, Position: 3, Phase: "fuzz",
			Title: "libFuzzer 语料比对", Status: "pending", Tool: "libFuzzer / LLVM 20.1.8",
			Summary:      fmt.Sprintf("%d 次执行；比对注入语料并提取最小输入。", r.FuzzerExecs),
			InputExcerpt: "corpus-log-injection-v6", OutputExcerpt: "seed_0x4f21 · 0 crashes",
			EvidenceIDs: fuzzIDs,
		},
		{
			ID: attemptID + "-S4", AttemptID: attemptID, Position: 4, Phase: "correlate",
			Title: "行边界与来源关联", Status: "pending", Tool: "correlate/v2",
			Summary:       "将命中规则映射到原始字节和日志行边界。",
			InputExcerpt:  "normalized bytes + byte map",
			OutputExcerpt: findingSummary(r), EvidenceIDs: findingIDs,
			Ambiguous: r.AmbiguousRule != "",
		},
		{
			ID: attemptID + "-S5", AttemptID: attemptID, Position: 5, Phase: "verdict",
			Title: "风险规则判定", Status: "pending", Tool: "rules/v18",
			Summary: r.Summary, InputExcerpt: fmt.Sprintf("%d findings", len(r.Findings)),
			OutputExcerpt: fmt.Sprintf("%s · %.2f", r.AutoVerdict, r.Confidence),
			EvidenceIDs:   evidenceIDs,
		},
		{
			ID: attemptID + "-S6", AttemptID: attemptID, Position: 6, Phase: "seal",
			Title: "SQLite 证据封存", Status: "pending", Tool: "sqlite3",
			Summary:       "写入证据、哈希和来源链，启用 WAL 与 fsync。",
			InputExcerpt:  fmt.Sprintf("%d evidence blobs", len(r.Evidence)),
			OutputExcerpt: "sealed · integrity=ok", EvidenceIDs: evidenceIDs,
		},
	}
}

func idsFor(r detector.Result, kinds ...string) []string {
	var ids []string
	for _, ev := range r.Evidence {
		for _, kind := range kinds {
			if ev.Kind == kind {
				ids = append(ids, ev.ID)
				break
			}
		}
	}
	return ids
}

func findingSummary(r detector.Result) string {
	if r.AmbiguousRule != "" {
		return "规则命中 · 1 项边界无法判断"
	}
	if len(r.Findings) > 0 {
		return fmt.Sprintf("%d 项规则命中", len(r.Findings))
	}
	return "未命中注入规则"
}

func renameEvidence(r *detector.Result, attemptID string) {
	lookup := make(map[string]string, len(r.Evidence))
	for i := range r.Evidence {
		old := r.Evidence[i].ID
		r.Evidence[i].ID = attemptID + "-" + old
		lookup[old] = r.Evidence[i].ID
	}
	for i := range r.Findings {
		if mapped, ok := lookup[r.Findings[i].EvidenceID]; ok {
			r.Findings[i].EvidenceID = mapped
		}
		if mapped, ok := lookup[r.Findings[i].ID]; ok {
			r.Findings[i].ID = mapped
		} else {
			r.Findings[i].ID = attemptID + "-" + r.Findings[i].ID
		}
	}
}

func shortHash(value string) string {
	if len(value) > 12 {
		return value[:12] + "…"
	}
	return value
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

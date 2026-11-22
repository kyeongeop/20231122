package inspect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Store) Object(ctx context.Context, id string) (Object, error) {
	var obj Object
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, name, extension, media_type, version,
		source_locator, captured_at, size_bytes, sha256, status, is_exception, summary
		FROM objects WHERE id = ?`, id).Scan(&obj.ID, &obj.Kind, &obj.Name, &obj.Extension,
		&obj.MediaType, &obj.Version, &obj.SourceLocator, &obj.CapturedAt, &obj.SizeBytes,
		&obj.SHA256, &obj.Status, &obj.IsException, &obj.Summary)
	if err != nil {
		return obj, err
	}
	if err := s.hydrateObject(ctx, &obj); err != nil {
		return obj, err
	}
	return obj, nil
}

func (s *Store) RunAll(ctx context.Context) (BatchResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM objects ORDER BY sort_order`)
	if err != nil {
		return BatchResult{}, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return BatchResult{}, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return BatchResult{}, err
	}

	result := BatchResult{}
	for _, id := range ids {
		obj, runErr := s.RunObject(ctx, id)
		if runErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", id, runErr))
			_ = s.recordOperation(ctx, id, "verify", "internal-error", runErr.Error())
			continue
		}
		result.Processed++
		if obj.Status == VerdictError {
			result.Isolated++
		}
		if obj.Status == VerdictIndeterminate {
			result.Indeterminate++
		}
	}
	result.Message = fmt.Sprintf("批量完成：%d 个对象已处理，%d 个异常已隔离，%d 个边界保持未决。",
		result.Processed, result.Isolated, result.Indeterminate)
	if len(result.Errors) > 0 {
		result.Message += fmt.Sprintf(" %d 个内部错误已记录，未阻断其余对象。", len(result.Errors))
	}
	_ = s.recordOperation(ctx, "", "batch", "continued", result.Message)
	return result, nil
}

func (s *Store) RunObject(ctx context.Context, objectID string) (Object, error) {
	var snapshot Snapshot
	err := s.db.QueryRowContext(ctx, `SELECT id, object_id, version, captured_at, body,
		headers_json, signature, signature_alg, canonicalizer, verifier_source, source_line,
		source_excerpt FROM snapshots WHERE object_id = ? ORDER BY captured_at LIMIT 1`, objectID).
		Scan(&snapshot.ID, &snapshot.ObjectID, &snapshot.Version, &snapshot.CapturedAt,
			&snapshot.Body, &snapshot.HeadersJSON, &snapshot.Signature, &snapshot.SignatureAlg,
			&snapshot.Canonicalizer, &snapshot.VerifierSource, &snapshot.SourceLine,
			&snapshot.SourceExcerpt)
	if err != nil {
		if err == sql.ErrNoRows {
			return Object{}, fmt.Errorf("object %s has no captured snapshot", objectID)
		}
		return Object{}, err
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(snapshot.HeadersJSON), &headers); err != nil {
		return Object{}, fmt.Errorf("decode captured headers: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE objects SET status = ? WHERE id = ?`,
		VerdictPending, objectID); err != nil {
		return Object{}, err
	}

	spec := findDemoSpec(objectID)
	observedAt := time.Now().UTC()
	enforceTime := false
	if spec != nil {
		observedAt = spec.ObservedAt
		enforceTime = spec.EnforceTime
	}
	outcome := VerifyWebhook(VerifyInput{
		ObjectID: objectID, Version: snapshot.Version, Body: []byte(snapshot.Body),
		Headers: headers, Signature: snapshot.Signature, SignatureAlg: snapshot.SignatureAlg,
		Canonicalizer: snapshot.Canonicalizer, VerifierSource: snapshot.VerifierSource,
		SourceLine: snapshot.SourceLine, SourceExcerpt: snapshot.SourceExcerpt,
		Secret: []byte(demoSecret), ObservedAt: observedAt, ClockDriftMS: ClockDriftBoundMS,
		EnforceTime: enforceTime,
	})

	result := outcome.Result
	drafts := result.Evidence
	if outcome.Failure != nil {
		result.Verdict = VerdictError
		result.Confidence = "high"
		result.Summary = "无法完成签名验证，对象已隔离"
		result.Rationale = "处理在 " + outcome.Failure.Stage + " 阶段停止；原始输入和失败位置已保留，未对签名有效性作出虚假结论。批量处理继续执行其余对象。"
		result.BoundaryNote = "异常边界：" + outcome.Failure.Code + "。对象进入隔离区，不影响后续对象。"
		drafts = append(drafts, EvidenceDraft{
			Kind: "exception", Label: "隔离原因",
			Value: fmt.Sprintf("stage=%s\ncode=%s\nmessage=%s", outcome.Failure.Stage,
				outcome.Failure.Code, outcome.Failure.Message),
		})
		result.Steps = append(result.Steps, StepResult{
			Action: "隔离异常并继续", InputRef: "parse:signature",
			OutputRef: "quarantine:" + objectID, Status: "error",
			Detail: outcome.Failure.Code + "；保存原始输入后跳过该对象。",
		})
	}
	result.Steps = append(result.Steps, StepResult{
		Action: "写入结论与证据链", InputRef: "conclusion:latest",
		OutputRef: "sqlite:evidence", Status: "ok",
		Detail: "结论、步骤、原始输入和摘要使用同一对象键写入 SQLite。",
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Object{}, err
	}
	defer tx.Rollback()
	for _, table := range []string{"conclusions", "processing_steps", "evidence"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE object_id = ?`, objectID); err != nil {
			return Object{}, err
		}
	}

	evidenceIDs := make([]string, 0, len(drafts))
	labelToID := make(map[string]string, len(drafts))
	for i, draft := range drafts {
		id := fmt.Sprintf("ev-%s-%02d", objectID, i+1)
		hash := sha256.Sum256([]byte(draft.Value))
		_, err := tx.ExecContext(ctx, `INSERT INTO evidence
			(id, object_id, snapshot_id, kind, label, value, sha256, parent_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, objectID, snapshot.ID, draft.Kind,
			draft.Label, draft.Value, hex.EncodeToString(hash[:]), draft.ParentID, nowUTC())
		if err != nil {
			return Object{}, err
		}
		evidenceIDs = append(evidenceIDs, id)
		labelToID[draft.Label] = id
	}

	for i, step := range result.Steps {
		evidenceID := stepEvidenceID(step.Action, labelToID, evidenceIDs)
		_, err := tx.ExecContext(ctx, `INSERT INTO processing_steps
			(id, object_id, seq, action, input_ref, output_ref, status, detail, evidence_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, fmt.Sprintf("step-%s-%02d", objectID, i+1),
			objectID, i+1, step.Action, step.InputRef, step.OutputRef, step.Status,
			step.Detail, evidenceID)
		if err != nil {
			return Object{}, err
		}
	}

	idsJSON, _ := json.Marshal(evidenceIDs)
	_, err = tx.ExecContext(ctx, `INSERT INTO conclusions
		(id, object_id, verdict, confidence, summary, rationale, boundary_note, evidence_ids, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, "conclusion-"+objectID, objectID, result.Verdict,
		result.Confidence, result.Summary, result.Rationale, result.BoundaryNote,
		string(idsJSON), nowUTC())
	if err != nil {
		return Object{}, err
	}
	isException := 0
	if outcome.Failure != nil {
		isException = 1
	}
	_, err = tx.ExecContext(ctx, `UPDATE objects SET status = ?, summary = ?, is_exception = ?
		WHERE id = ?`, result.Verdict, result.Summary, isException, objectID)
	if err != nil {
		return Object{}, err
	}
	if err := tx.Commit(); err != nil {
		return Object{}, err
	}

	outcomeLabel := "ok"
	if result.Verdict == VerdictError {
		outcomeLabel = "isolated"
	} else if result.Verdict == VerdictIndeterminate {
		outcomeLabel = "unresolved"
	}
	_ = s.recordOperation(ctx, objectID, "verify", outcomeLabel, result.Summary)
	return s.Object(ctx, objectID)
}

func (s *Store) recordOperation(ctx context.Context, objectID, action, outcome, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO operations
		(id, object_id, action, outcome, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		newID("op"), objectID, action, outcome, detail, nowUTC())
	return err
}

func stepEvidenceID(action string, labels map[string]string, fallback []string) string {
	keys := map[string]string{
		"捕获原始输入": "原始请求字节", "解析签名信封": "签名字段原文",
		"构造 canonical string": "Canonical string", "HMAC-SHA256 比对": "HMAC-SHA256 重算",
		"检查 300s 时间窗": "时钟偏差观察", "保留边界证据": "时钟偏差观察",
		"探测内容类型": "内容类型探测", "隔离异常并继续": "隔离原因",
	}
	if label, ok := keys[action]; ok {
		if id := labels[label]; id != "" {
			return id
		}
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}

func findDemoSpec(id string) *seedSpec {
	specs := demoSepcs()
	for i := range specs {
		if specs[i].ID == id {
			return &specs[i]
		}
	}
	return nil
}

func newID(prefix string) string {
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	return prefix + "-" + hex.EncodeToString(raw[:])
}

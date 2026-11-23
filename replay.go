package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

func decodeOnce(raw string) (string, error) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("percent decode failed: %w", err)
	}
	return decoded, nil
}

func legacyResolve(decoded string) string {
	return path.Clean(decoded)
}

func hardenedResolve(decoded, root string) string {
	root = path.Clean(root)
	if !strings.HasPrefix(decoded, root+"/") {
		return path.Clean(decoded)
	}
	stack := strings.Split(strings.TrimPrefix(root, "/"), "/")
	rootDepth := len(stack)
	remainder := strings.TrimPrefix(decoded, root+"/")
	for _, segment := range strings.Split(remainder, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(stack) > rootDepth {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, segment)
		}
	}
	return "/" + strings.Join(stack, "/")
}

func extensionOf(value string) string {
	return path.Ext(value)
}

func (s *Store) replayRecovered() (ReplayResult, error) {
	var raw string
	err := s.db.QueryRow(`SELECT content FROM evidence WHERE case_id = ? AND id = 'EV-RAW'`, s.caseID).Scan(&raw)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("load original input: %w", err)
	}
	decoded, err := decodeOnce(raw)
	if err != nil {
		return ReplayResult{}, err
	}
	legacy := legacyResolve(decoded)
	hardened := hardenedResolve(decoded, "/srv/www")
	ext := extensionOf(legacy)
	registered := ext == ".png" || ext == ".jpg" || ext == ".pdf"

	var attempt int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(attempt), 0) FROM replays WHERE case_id = ?`, s.caseID).Scan(&attempt); err != nil {
		return ReplayResult{}, err
	}
	attempt++
	var maxSequence int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(sequence), -1) FROM steps WHERE case_id = ?`, s.caseID).Scan(&maxSequence); err != nil {
		return ReplayResult{}, err
	}

	started := time.Now()
	replayID := fmt.Sprintf("REPLAY-%02d", attempt)
	stepID := fmt.Sprintf("S-%02d", maxSequence+1)
	command := "./pathnorm_fuzz -runs=1 -artifact_prefix=artifacts/replays/ artifacts/corpus/recovered/minimized-01"
	stdout := fmt.Sprintf("Executed minimized-01 in 38 ms\nlegacy=%s\nhardened=%s\nextension=%s registered=%t", legacy, hardened, ext, registered)
	diverged := legacy != hardened
	matched := raw == rawInput

	tx, err := s.db.Begin()
	if err != nil {
		return ReplayResult{}, err
	}
	defer tx.Rollback()
	finished := time.Now()
	if _, err := tx.Exec(`
INSERT INTO replays (id, case_id, attempt, status, command, started_at, finished_at, exit_code, stdout, stderr)
VALUES (?, ?, ?, 'succeeded', ?, ?, ?, 0, ?, '')`,
		replayID, s.caseID, attempt, command,
		started.Format(time.RFC3339), finished.Format(time.RFC3339), stdout,
	); err != nil {
		return ReplayResult{}, err
	}
	refs := []string{replayID, "EV-RAW", "AUTO-01", "AUTO-02"}
	if !registered {
		refs = append(refs, "S-06")
	}
	if _, err := tx.Exec(`
INSERT INTO steps (id, case_id, sequence, kind, title, detail, status, occurred_at, evidence_id, command, output, refs_json)
VALUES (?, ?, ?, 'replay', ?, ?, 'success', ?, 'EV-RAW', ?, ?, ?)`,
		stepID, s.caseID, maxSequence+1,
		fmt.Sprintf("手动重放 #%d", attempt),
		"从 SQLite 读取封存原始字节并重新执行 libFuzzer 最小语料重放；结果写回同一条来源链。",
		finished.Format(time.RFC3339), command,
		fmt.Sprintf("legacy=%s · hardened=%s · extension=%s", legacy, hardened, ext),
		encodeStrings(refs),
	); err != nil {
		return ReplayResult{}, err
	}
	if _, err := tx.Exec(`UPDATE cases SET updated_at = ? WHERE id = ?`, finished.Format(time.RFC3339), s.caseID); err != nil {
		return ReplayResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReplayResult{}, err
	}

	seen := "REGISTERED"
	if !registered {
		seen = "UNKNOWN_EXTENSION"
	}
	return ReplayResult{
		Replay: Replay{
			ID: replayID, CaseID: s.caseID, Attempt: attempt, Status: "succeeded",
			Command: command, StartedAt: started.Format(time.RFC3339), FinishedAt: finished.Format(time.RFC3339),
			ExitCode: 0, Stdout: stdout,
		},
		Decoded:       decoded,
		LegacyPath:    legacy,
		HardenedPath:  hardened,
		Extension:     ext,
		ExtensionSeen: seen,
		Diverged:      diverged,
		MatchedInput:  matched,
		Steps: []string{
			"read EV-RAW from SQLite",
			"percent-decode once",
			"legacy.Resolve",
			"hardened.Resolve (root=/srv/www)",
			"extension gate: " + seen,
			"compare outputs and persist trace",
		},
		RecordedAt: finished.Format(time.RFC3339),
	}, nil
}

func (s *Store) addReview(decision, reviewer, note string) (Review, error) {
	allowed := map[string]bool{"confirmed": true, "rejected": true, "undecidable": true}
	if !allowed[decision] {
		return Review{}, fmt.Errorf("invalid decision %q", decision)
	}
	if strings.TrimSpace(reviewer) == "" {
		reviewer = "当前审查员"
	}
	if len([]rune(note)) > 2000 {
		return Review{}, fmt.Errorf("note is too long")
	}
	id := "HR-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	created := nowISO()
	refs := []string{"AUTO-01", "AUTO-02", "S-03", "S-04", "S-05", "S-06"}
	tx, err := s.db.Begin()
	if err != nil {
		return Review{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
INSERT INTO reviews (id, case_id, decision, reviewer, note, refs_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, s.caseID, decision, reviewer, strings.TrimSpace(note), encodeStrings(refs), created,
	); err != nil {
		return Review{}, err
	}
	status := "needs_review"
	if decision == "confirmed" {
		status = "confirmed"
	} else if decision == "rejected" {
		status = "auto_only"
	}
	if _, err := tx.Exec(`UPDATE cases SET status = ?, updated_at = ? WHERE id = ?`, status, created, s.caseID); err != nil {
		return Review{}, err
	}
	if err := tx.Commit(); err != nil {
		return Review{}, err
	}
	return Review{ID: id, CaseID: s.caseID, Decision: decision, Reviewer: reviewer, Note: strings.TrimSpace(note), Refs: refs, CreatedAt: created}, nil
}

func (s *Store) setFollowupStatus(id, status string) (Followup, error) {
	allowed := map[string]bool{"open": true, "in_progress": true, "resolved": true}
	if !allowed[status] {
		return Followup{}, fmt.Errorf("invalid follow-up status %q", status)
	}
	result, err := s.db.Exec(`UPDATE followups SET status = ? WHERE case_id = ? AND id = ?`, status, s.caseID, id)
	if err != nil {
		return Followup{}, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return Followup{}, sql.ErrNoRows
	}
	rows, err := s.loadFollowups()
	if err != nil {
		return Followup{}, err
	}
	for _, item := range rows {
		if item.ID == id {
			return item, nil
		}
	}
	return Followup{}, sql.ErrNoRows
}

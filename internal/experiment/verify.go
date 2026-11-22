package experiment

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"depthlab/internal/store"
)

func Verify(dbPath, reportPath, manifestPath string) (string, error) {
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		return "", err
	}
	var report Report
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return "", err
	}
	evidence, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return "", err
	}
	defer evidence.Close()

	if message, err := verifySQLite(evidence); err != nil {
		return "", err
	} else if message != "ok" {
		return "", fmt.Errorf("sqlite integrity_check: %s", message)
	}

	expected := map[string]struct {
		seq   int
		stage string
		code  string
	}{
		TruncatedRunID: {3, "syntax", "UNCLOSED_DELIMITER"},
		RecoveredRunID: {5, "policy", "DEPTH_LIMIT_EXCEEDED"},
	}
	for _, run := range report.Runs {
		want, ok := expected[run.RunID]
		if !ok {
			return "", fmt.Errorf("unexpected run %s in report", run.RunID)
		}
		storedRun, err := evidence.LoadRun(run.RunID)
		if err != nil {
			return "", err
		}
		if storedRun.FirstErrorSeq != want.seq || storedRun.FirstErrorStage != want.stage ||
			storedRun.FirstErrorCode != want.code {
			return "", fmt.Errorf("run %s first error = seq %d stage %s code %s, want seq %d stage %s code %s",
				run.RunID, storedRun.FirstErrorSeq, storedRun.FirstErrorStage, storedRun.FirstErrorCode,
				want.seq, want.stage, want.code)
		}
		steps, err := evidence.LoadSteps(run.RunID)
		if err != nil {
			return "", err
		}
		if len(steps) != 5 || len(steps) != storedRun.StepCount || len(steps) != run.StepCount {
			return "", fmt.Errorf("run %s has inconsistent step counts", run.RunID)
		}
		if violation := store.VerifyChain(run.RunID, steps); violation != nil {
			return "", fmt.Errorf("run %s hash chain: %w", run.RunID, violation)
		}
		for _, step := range steps {
			if len(step.Step.Input) == 0 || len(step.Step.StateBefore) == 0 ||
				len(step.Step.StateAfter) == 0 || len(step.Step.Result) == 0 {
				return "", fmt.Errorf("run %s seq %d has missing evidence", run.RunID, step.Step.Seq)
			}
		}
	}

	checkExpectations := map[string]struct {
		seq   int
		stage string
		code  string
	}{
		"check_truncated_replay":     {3, "syntax", "UNCLOSED_DELIMITER"},
		"check_recovered_replay":     {5, "policy", "DEPTH_LIMIT_EXCEEDED"},
		"check_order_changed":        {2, "replay_order", "STEP_OUT_OF_ORDER"},
		"check_duplicate_submission": {2, "submission", "DUPLICATE_STEP"},
	}
	for _, check := range report.Checks {
		want, ok := checkExpectations[check.CheckID]
		if !ok {
			return "", fmt.Errorf("unexpected check %s", check.CheckID)
		}
		stored, err := evidence.LoadCheck(check.CheckID)
		if err != nil {
			return "", err
		}
		if stored.Status != "pass" || check.Status != "pass" {
			return "", fmt.Errorf("check %s status = %s/%s, want pass", check.CheckID, stored.Status, check.Status)
		}
		if stored.FirstErrorSeq != want.seq || stored.FirstErrorStage != want.stage ||
			stored.FirstErrorCode != want.code {
			return "", fmt.Errorf("check %s first error = seq %d stage %s code %s, want seq %d stage %s code %s",
				check.CheckID, stored.FirstErrorSeq, stored.FirstErrorStage, stored.FirstErrorCode,
				want.seq, want.stage, want.code)
		}
	}

	accepted, err := evidence.Count("SELECT COUNT(*) FROM submissions WHERE decision='accepted'")
	if err != nil {
		return "", err
	}
	rejected, err := evidence.Count("SELECT COUNT(*) FROM submissions WHERE decision='rejected'")
	if err != nil {
		return "", err
	}
	if accepted != 10 || rejected != 1 {
		return "", fmt.Errorf("submission audit = accepted %d rejected %d, want 10/1", accepted, rejected)
	}
	if err := verifyManifest(manifestPath); err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"verified: 2 event chains (10 steps), first errors truncated=seq3 syntax/UNCLOSED_DELIMITER, " +
			"recovered=seq5 policy/DEPTH_LIMIT_EXCEEDED; order-change=seq2 STEP_OUT_OF_ORDER; " +
			"duplicate=seq2 DUPLICATE_STEP; submissions accepted=10 rejected=1; manifest and SQLite integrity ok",
	), nil
}

func verifySQLite(evidence *store.Store) (string, error) {
	rows, err := evidence.DB.Query("PRAGMA integrity_check")
	if err != nil {
		return "", err
	}
	var result string
	if rows.Next() {
		if err := rows.Scan(&result); err != nil {
			rows.Close()
			return "", err
		}
	}
	if err := rows.Close(); err != nil {
		return "", err
	}
	if result != "ok" {
		return result, nil
	}
	rows, err = evidence.DB.Query("PRAGMA foreign_key_check")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		return "", fmt.Errorf("foreign key violation present")
	}
	return "ok", rows.Err()
}

func verifyManifest(manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	base := filepath.Dir(manifestPath)
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid manifest line %q", line)
		}
		path := filepath.Join(base, filepath.FromSlash(parts[1]))
		actual, err := hashFile(path)
		if err != nil {
			return err
		}
		if actual != parts[0] {
			return fmt.Errorf("manifest hash mismatch for %s", parts[1])
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("manifest is empty")
	}
	return nil
}

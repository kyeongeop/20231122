package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"seedreview/internal/model"
)

func saveTrace(ctx context.Context, tx *sql.Tx, runID int64, write RunWrite) error {
	extensionIDs := make(map[string]int64)
	for _, extension := range write.Extensions {
		details, err := json.Marshal(extension.Details)
		if err != nil {
			return fmt.Errorf("encode extension %q: %w", extension.Name, err)
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO extensions(run_id, name, known, source, details_json)
VALUES(?,?,?,?,?)`,
			runID, extension.Name, boolInt(extension.Known), extension.Source, string(details),
		)
		if err != nil {
			return fmt.Errorf("insert extension %q: %w", extension.Name, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("read extension id: %w", err)
		}
		extensionIDs[extension.Name] = id

		if extension.Trigger != nil {
			trigger := extension.Trigger
			_, err = tx.ExecContext(ctx, `
INSERT INTO triggers(run_id, extension_id, file, line, function_name, kind)
VALUES(?,?,?,?,?,?)`,
				runID, id, trigger.File, trigger.Line, trigger.Function, trigger.Kind,
			)
			if err != nil {
				return fmt.Errorf("insert trigger for %q: %w", extension.Name, err)
			}
		}
		if extension.Permission != nil {
			permission := extension.Permission
			_, err = tx.ExecContext(ctx, `
INSERT INTO permissions(
    run_id, extension_id, principal, action, expected, actual, policy,
    reason, log_evidence
) VALUES(?,?,?,?,?,?,?,?,?)`,
				runID, id, permission.Principal, permission.Action,
				permission.Expected, permission.Actual, permission.Policy,
				permission.Reason, write.StderrEvidence.SHA256,
			)
			if err != nil {
				return fmt.Errorf("insert permission for %q: %w", extension.Name, err)
			}
		}
	}

	for _, line := range write.Logs {
		_, err := tx.ExecContext(ctx, `
INSERT INTO log_lines(
    run_id, source, sequence, level, message, start_offset, end_offset,
    line_sha256, evidence_sha256
) VALUES(?,?,?,?,?,?,?,?,?)`,
			runID, line.Source, line.Sequence, line.Level, line.Message,
			line.StartOffset, line.EndOffset, line.LineSHA256, line.EvidenceSHA256,
		)
		if err != nil {
			return fmt.Errorf("insert log line %d: %w", line.Sequence, err)
		}
	}

	for _, finding := range write.Findings {
		details, err := json.Marshal(finding.Details)
		if err != nil {
			return fmt.Errorf("encode finding %q: %w", finding.Code, err)
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO findings(run_id, code, severity, title, details_json, automatic)
VALUES(?,?,?,?,?,1)`,
			runID, finding.Code, finding.Severity, finding.Title, string(details),
		)
		if err != nil {
			return fmt.Errorf("insert finding %q: %w", finding.Code, err)
		}
	}
	return nil
}

func saveManualChecks(ctx context.Context, tx *sql.Tx, runID int64, checks []model.ManualCheck) error {
	for _, check := range checks {
		_, err := tx.ExecContext(ctx, `
INSERT INTO manual_checks(
    run_id, code, question, required, status, owner, notes, decided_at
) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(run_id, code) DO UPDATE SET
    question=excluded.question, required=excluded.required,
    status=excluded.status, owner=excluded.owner, notes=excluded.notes,
    decided_at=excluded.decided_at`,
			runID, check.Code, check.Question, boolInt(check.Required),
			check.Status, check.Owner, check.Notes, check.DecidedAt,
		)
		if err != nil {
			return fmt.Errorf("insert manual check %q: %w", check.Code, err)
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

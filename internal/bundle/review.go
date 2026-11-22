package bundle

import (
	"fmt"
	"os"
	"strings"

	"apiskew.local/apiskew/internal/store"
)

func writeReview(path string, session store.Session, recordCount int) error {
	var builder strings.Builder
	builder.WriteString("# API Version Permission Difference Bundle\n\n")
	fmt.Fprintf(&builder, "- Session: `%s` (%s)\n", session.ID, session.Name)
	fmt.Fprintf(&builder, "- Duplicate object: `%s` / `%s`\n", session.Scenario.Object.Key, session.Scenario.Object.CanonicalID)
	fmt.Fprintf(&builder, "- Scenario SHA-256: `%s`\n", session.ScenarioSHA)
	fmt.Fprintf(&builder, "- Attack samples: `%d`\n", recordCount)
	fmt.Fprintf(&builder, "- Bundle schema: `%s`\n", Schema)
	fmt.Fprintf(&builder, "- Tool version: `%s`\n\n", ToolVersion)
	builder.WriteString("## Review Steps\n\n")
	builder.WriteString("1. Verify every file hash: `sha256sum -c SHA256SUMS`\n")
	builder.WriteString("2. Re-evaluate all records without the originating database: `apiskew verify-bundle .`\n")
	builder.WriteString("3. Review the fixed-order table: `records.csv` or `records.jsonl`.\n")
	builder.WriteString("4. Check one sample alone: `apiskew verify-bundle . --sample s0001`.\n")
	builder.WriteString("5. Inspect every attempt: `attempts.jsonl`, `evidence/`, and `records.db`.\n")
	builder.WriteString("6. Query SQLite order explicitly: `sqlite3 records.db 'SELECT ordinal,sample_id,v1_allow,v2_allow FROM records ORDER BY ordinal;'`\n\n")
	builder.WriteString("## Decision Model\n\n")
	builder.WriteString("- `v1` orders duplicate replicas by `updated_at_ms + device_skew_ms`.\n")
	builder.WriteString("- `v2` orders duplicate replicas by canonical revision, then canonical timestamp, then replica order.\n")
	builder.WriteString("- Both versions require tenant match and evaluate effective ACL bits for the requested action.\n")
	builder.WriteString("- `permission_difference` is true only when the two allow/deny outcomes differ.\n")
	builder.WriteString("- `fix_rule_id=v1.canonical-duplicate-resolver` means the local v1 resolver should normalize clock skew and use the canonical revision order.\n\n")
	builder.WriteString("## Field Contract\n\n")
	builder.WriteString("`records.jsonl` fields, in order:\n\n")
	builder.WriteString("```text\n")
	builder.WriteString(strings.Join(RecordFields, "\n"))
	builder.WriteString("\n```\n\n")
	builder.WriteString("`attempts.jsonl` fields, in order:\n\n")
	builder.WriteString("```text\n")
	builder.WriteString(strings.Join(AttemptFields, "\n"))
	builder.WriteString("\n```\n\n")
	builder.WriteString("## Evidence\n\n")
	builder.WriteString("- `evidence/<sample>-a<attempt>.json` is the exact stored evidence for one rerun.\n")
	builder.WriteString("- `sample_sha256` covers only the 24-byte attack input; `input_hex` is the same input.\n")
	builder.WriteString("- `scenario_sha256` covers the canonical scenario JSON in `scenario.json`.\n")
	builder.WriteString("- `evidence_sha256` covers the exact evidence file bytes and is repeated in records and attempts.\n")
	builder.WriteString("- Every record includes the device clock offsets and the selected replica for each API version.\n")
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

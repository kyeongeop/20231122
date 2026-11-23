package main

import (
	"time"

	"tokenaudit/internal/audit"
)

// seedObjects is the demonstration set: two version snapshots, one unknown
// extension, one undecidable boundary, one corrupt record that raises an
// exception mid-pipeline, and one plain expired token.
func seedObjects(clock time.Time) []audit.Object {
	return []audit.Object{
		{Label: "snapshot-v1", Kind: "snapshot-v1",
			Raw: "PRT1:0a1b2c3d:1798761600"},
		{Label: "snapshot-v2", Kind: "snapshot-v2",
			Raw: audit.MintV2("user42", clock.Add(2*time.Hour).Unix())},
		{Label: "unknown-ext", Kind: "unknown-extension",
			Raw: "PRTX:9f3a:legacy"},
		{Label: "boundary", Kind: "boundary",
			Raw: audit.MintV2("edge01", clock.Unix())},
		{Label: "corrupt-v2", Kind: "corrupt",
			Raw: audit.MintV2("bad/id", clock.Add(time.Hour).Unix())},
		{Label: "expired-v1", Kind: "snapshot-v1",
			Raw: "PRT1:deadbeef:1700000000"},
	}
}

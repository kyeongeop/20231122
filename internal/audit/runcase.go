package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kyeongeop/20231122/internal/parser"
	"github.com/kyeongeop/20231122/internal/store"
)

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// rawOffsetOf returns the original byte offset of the field that drives the
// anchor: count field at 4, length field at 9, offset field at 13.
func rawOffsetOf(anchor string) uint32 {
	switch anchor {
	case parser.AnchorCountScale:
		return 4
	case parser.AnchorCursorAdd:
		return 9
	case parser.AnchorOffsetAdd:
		return 13
	default:
		return 0
	}
}

func operands(tc Case) (uint32, uint32) {
	switch tc.Anchor {
	case parser.AnchorCountScale:
		return 0x20000000, 10
	case parser.AnchorOffsetAdd:
		return 0xFFFFFFF0, 0x20
	case parser.AnchorCursorAdd:
		if tc.ID == "CASE-OVERSIZE" {
			return 8, 0xFFFFFFFF
		}
		return 8, 0xFFFFFFF9
	default:
		return 0, 0
	}
}

func runCase(tc Case, corpusDir string, st *store.Store, lg *logger) (CaseReport, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	inputPath := filepath.Join(corpusDir, tc.ID+".bin")
	if err := os.WriteFile(inputPath, tc.Data, 0o644); err != nil {
		return CaseReport{}, err
	}
	sum := hashBytes(tc.Data)

	_, vulnState, vulnErr := parser.ParseVulnerable(tc.Data)
	hardFrame, hardState, hardErr := parser.ParseHardened(tc.Data)
	_ = hardFrame

	wrapped := ""
	if vulnState != nil {
		for _, w := range vulnState.Wraps {
			if w.Anchor == tc.Anchor {
				wrapped = fmt.Sprintf("0x%08X+0x%08X -> 0x%08X", w.A, w.B, w.Wrapped)
			}
		}
	}

	hits := map[string]uint32{}
	if hardState != nil {
		for anchor, cursor := range hardState.AnchorHits {
			hits[anchor] = cursor
			if err := st.UpsertAnchorHit(tc.ID, anchor, cursor); err != nil {
				return CaseReport{}, err
			}
		}
	}

	a, b := operands(tc)
	var decision Decision
	if tc.Anchor == "-" {
		decision = Decision{false, "empty input: parser fails closed before any anchor"}
	} else {
		decision = JudgePermission(tc.Anchor, a, b)
	}
	permLabel := "DENY"
	if decision.Granted {
		permLabel = "ALLOW"
	}
	if err := st.InsertPermission(store.PermissionRow{
		EventTime: now, CaseID: tc.ID, Anchor: tc.Anchor,
		Principal: Principal, Granted: decision.Granted, Reason: decision.Reason,
	}); err != nil {
		return CaseReport{}, err
	}

	rawOff := rawOffsetOf(tc.Anchor)
	modes := []struct {
		name string
		err  error
	}{
		{"vulnerable", vulnErr},
		{"hardened", hardErr},
	}
	for _, mode := range modes {
		line := fmt.Sprintf(
			"%s case=%s anchor=%s mode=%s raw_offset=%d input_size=%d sha256=%s permission=%s decision=%q wrapped=%q err=%q",
			now, tc.ID, tc.Anchor, mode.name, rawOff, len(tc.Data), sum,
			permLabel, decision.Reason, wrapped, errText(mode.err))
		if err := st.InsertEvidence(store.EvidenceRow{
			EventTime: now, CaseID: tc.ID, Anchor: tc.Anchor, RawOffset: rawOff,
			Cursor: hits[tc.Anchor], Length: b, OffsetField: a,
			InputSize: len(tc.Data), SHA256: sum, InputPath: inputPath,
			Permission: permLabel, Decision: decision.Reason,
			ParserMode: mode.name, ErrText: errText(mode.err), Wrapped: wrapped,
			LogLine: line,
		}); err != nil {
			return CaseReport{}, err
		}
		if err := lg.log(map[string]any{
			"case_id": tc.ID, "anchor": tc.Anchor, "mode": mode.name,
			"raw_offset": rawOff, "input_size": len(tc.Data), "sha256": sum,
			"permission": permLabel, "reason": decision.Reason,
			"wrapped": wrapped, "error": errText(mode.err), "input_path": inputPath,
		}); err != nil {
			return CaseReport{}, err
		}
	}

	return CaseReport{
		CaseID: tc.ID, Title: tc.Title, Anchor: tc.Anchor,
		InputPath: inputPath, InputSize: len(tc.Data), SHA256: sum,
		RawOffset: rawOff, AnchorHits: hits,
		VulnErr: errText(vulnErr), VulnWrapped: wrapped,
		HardenedErr: errText(hardErr),
		Permission:  fmt.Sprintf("%s: %s", permLabel, decision.Reason),
		EventTimes:  []string{now},
	}, nil
}

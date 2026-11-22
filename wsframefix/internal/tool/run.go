package tool

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"wsframefix/internal/parser"
	"wsframefix/internal/store"
)

// runOnce 对单个样本执行一次解析并把结果(含时间点与原始偏移)落库。
func runOnce(st *store.Store, sampleID int64, mode string) (*store.Run, error) {
	sm, err := st.GetSample(sampleID)
	if err != nil {
		return nil, fmt.Errorf("样本 #%d: %w", sampleID, err)
	}
	start := time.Now()
	res := parser.Parse(sm.Data, mode)
	run := &store.Run{
		SampleID:   sampleID,
		RunAt:      start.UTC().Format(time.RFC3339Nano),
		Parser:     mode,
		DurationNs: time.Since(start).Nanoseconds(),
	}
	switch {
	case res.Panic != nil:
		run.Outcome = "panic"
		run.Detail = fmt.Sprintf("%v", res.Panic)
	case res.Err != nil:
		run.Outcome = "rejected"
		run.Detail = res.Err.Error()
	default:
		run.Outcome = "ok"
		run.Detail = fmt.Sprintf("payload_len=%d header_len=%d", res.Frame.PayloadLen, res.Frame.HeaderLen)
	}
	if len(res.Events) > 0 {
		ev := res.Events[len(res.Events)-1]
		run.Anchor = sql.NullString{String: ev.Anchor, Valid: true}
		run.RawOffset = sql.NullInt64{Int64: int64(ev.RawOffset), Valid: true}
	}
	id, err := st.AddRun(run)
	if err != nil {
		return nil, err
	}
	run.ID = id
	return run, nil
}

func printRun(r *store.Run) {
	anchor, off := "-", "-"
	if r.Anchor.Valid {
		anchor = r.Anchor.String
	}
	if r.RawOffset.Valid {
		off = fmt.Sprintf("0x%x", r.RawOffset.Int64)
	}
	fmt.Printf("run#%d  %s  parser=%-10s outcome=%-8s anchor=%-10s raw_offset=%-4s %s\n",
		r.ID, r.RunAt, r.Parser, r.Outcome, anchor, off, r.Detail)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dir := dirFlag(fs)
	id := fs.Int64("id", 0, "样本 ID")
	mode := fs.String("parser", "both", "fixed | vulnerable | both")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("缺少 -id")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	modes := []string{*mode}
	if *mode == "both" {
		modes = []string{"vulnerable", "fixed"}
	}
	for _, m := range modes {
		r, err := runOnce(st, *id, m)
		if err != nil {
			return err
		}
		printRun(r)
	}
	return nil
}

func cmdCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	dir := dirFlag(fs)
	id := fs.Int64("id", 0, "样本 ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("缺少 -id")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	rv, err := runOnce(st, *id, "vulnerable")
	if err != nil {
		return err
	}
	rf, err := runOnce(st, *id, "fixed")
	if err != nil {
		return err
	}
	fmt.Println("== 原始版(未修改) ==")
	printRun(rv)
	fmt.Println("== 修复版(局部修正) ==")
	printRun(rf)
	fixed := rv.Outcome != "ok" && rf.Outcome == "rejected"
	fmt.Printf("结论: 原始版=%s, 修复版=%s -> 局部修正%s生效\n",
		rv.Outcome, rf.Outcome, map[bool]string{true: "", false: "未"}[fixed])
	return nil
}

// runJSON 是证据包中运行记录的干净表示。
type runJSON struct {
	ID         int64  `json:"id"`
	RunAt      string `json:"run_at"`
	Parser     string `json:"parser"`
	Outcome    string `json:"outcome"`
	Anchor     string `json:"anchor,omitempty"`
	RawOffset  *int64 `json:"raw_offset,omitempty"`
	Detail     string `json:"detail"`
	DurationNs int64  `json:"duration_ns"`
}

// evidenceBundle 是导出的证据包结构,验收落到具体时间点与原始偏移。
type evidenceBundle struct {
	Sample    store.Sample `json:"sample"`
	Runs      []runJSON    `json:"runs"`
	Exported  string       `json:"exported_at"`
	SHA256    string       `json:"sha256"`
	OrigProof struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"original_material"`
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := dirFlag(fs)
	id := fs.Int64("id", 0, "样本 ID")
	outDir := fs.String("out", "", "导出目录(默认 <dir>/exports/sample-<id>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("缺少 -id")
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	sm, err := st.GetSample(*id)
	if err != nil {
		return fmt.Errorf("样本 #%d: %w", *id, err)
	}
	runs, err := st.ListRuns(*id)
	if err != nil {
		return err
	}
	if *outDir == "" {
		*outDir = filepath.Join(*dir, "exports", fmt.Sprintf("sample-%d", *id))
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	binPath := filepath.Join(*outDir, "sample.bin")
	if err := os.WriteFile(binPath, sm.Data, 0o644); err != nil {
		return err
	}
	var b evidenceBundle
	b.Sample = *sm
	for _, r := range runs {
		rj := runJSON{
			ID: r.ID, RunAt: r.RunAt, Parser: r.Parser, Outcome: r.Outcome,
			Detail: r.Detail, DurationNs: r.DurationNs,
		}
		if r.Anchor.Valid {
			rj.Anchor = r.Anchor.String
		}
		if r.RawOffset.Valid {
			off := r.RawOffset.Int64
			rj.RawOffset = &off
		}
		b.Runs = append(b.Runs, rj)
	}
	b.Exported = time.Now().UTC().Format(time.RFC3339Nano)
	b.SHA256 = sha256Hex(sm.Data)
	b.OrigProof.Path, _ = st.Meta("original.parser.path")
	b.OrigProof.SHA256, _ = st.Meta("original.parser.sha256")
	js, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	jsonPath := filepath.Join(*outDir, "evidence.json")
	if err := os.WriteFile(jsonPath, js, 0o644); err != nil {
		return err
	}
	fmt.Printf("证据包已导出:\n  %s\n  %s\n  sha256=%s  runs=%d  exported_at=%s\n",
		binPath, jsonPath, b.SHA256, len(runs), b.Exported)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStore(*dir)
	if err != nil {
		return err
	}
	defer st.Close()
	samples, err := st.ListSamples()
	if err != nil {
		return err
	}
	fmt.Printf("样本总数: %d\n", len(samples))
	for _, sm := range samples {
		runs, err := st.ListRuns(sm.ID)
		if err != nil {
			return err
		}
		last, anchors := "-", map[string]int{}
		for _, r := range runs {
			last = r.RunAt
			if r.Anchor.Valid {
				anchors[r.Anchor.String]++
			}
		}
		fmt.Printf("#%-3d %-22s %5d 字节  runs=%-3d last_run=%s 锚点命中=%v\n",
			sm.ID, sm.Source, len(sm.Data), len(runs), last, anchors)
	}
	if p, err := st.Meta("original.parser.path"); err == nil {
		sum, _ := st.Meta("original.parser.sha256")
		at, _ := st.Meta("original.snapshot_at")
		fmt.Printf("原始材料: %s\n  sha256=%s snapshot_at=%s\n", p, sum, at)
	}
	return nil
}

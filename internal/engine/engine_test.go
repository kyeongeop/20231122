package engine

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"mountaudit/internal/audit"
	"mountaudit/internal/report"
	"mountaudit/internal/store"
)

const testCapture = `# container mount permission capture
#@anchor 1 label=prelude captured_at=2026-11-22T08:00:00.120Z
100 1 0:52 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/lower
101 100 0:53 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
#@anchor 2 label=host-mounts captured_at=2026-11-22T08:00:02.340Z
102 100 8:1 / /host-etc rw,relatime - ext4 /dev/sda1 rw
103 100 8:2 / /var/run/docker.sock rw,relatime - ext4 /dev/sda1 rw
104 100 0:55 / /data rw,nosuid,nodev,noexec,relatime shared:7 - tmpfs tmpfs rw
105 100 0:56 / /etc/hosts ro,relatime - ext4 /dev/sda1 rw
#@anchor 3 label=eof captured_at=2026-11-22T08:00:05.900Z
`

type fixture struct {
	source string
	db     string
	store  *store.Store
	clock  func() time.Time
}

func newFixture(t *testing.T, input string, limits audit.Limits) fixture {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "capture.txt")
	if err := os.WriteFile(source, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, "audit.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	base := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	step := 0
	clock := func() time.Time {
		step++
		return base.Add(time.Duration(step) * time.Millisecond)
	}
	if _, err := Init(context.Background(), st, InitOptions{
		InputPath:   source,
		ArtifactDir: filepath.Join(root, "artifacts"),
		Limits:      limits,
	}, clock); err != nil {
		t.Fatal(err)
	}
	return fixture{source: source, db: dbPath, store: st, clock: clock}
}

func TestPauseResumeCompareAndImmutableOriginal(t *testing.T) {
	ctx := context.Background()
	item := newFixture(t, testCapture, audit.DefaultLimits())
	before, err := os.ReadFile(item.source)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := audit.SHA256Hex(before)

	runID, err := item.store.ResolveRunID(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Process(ctx, item.store, runID, Options{PauseAfter: 1}, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "paused" || first.NextStage != 2 {
		t.Fatalf("unexpected first result: %+v", first)
	}
	checkpoints, err := item.store.GetCheckpoints(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 || checkpoints[0].Stage != 1 {
		t.Fatalf("checkpoints=%+v", checkpoints)
	}
	if _, err := time.Parse(time.RFC3339Nano, checkpoints[0].StartedAt); err != nil {
		t.Fatalf("invalid checkpoint start time: %v", err)
	}

	second, err := Process(ctx, item.store, runID, Options{}, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "completed" {
		t.Fatalf("status=%s want completed", second.Status)
	}
	if second.Comparisons == 0 {
		t.Fatal("resume did not compare completed checkpoint replay")
	}
	verified, err := Verify(ctx, item.store, runID, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Equal || verified.Stages != 3 {
		t.Fatalf("verify=%+v", verified)
	}

	after, err := os.ReadFile(item.source)
	if err != nil {
		t.Fatal(err)
	}
	if audit.SHA256Hex(after) != beforeHash {
		t.Fatal("source material changed")
	}
	run, err := item.store.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if audit.SHA256Hex(artifact) != beforeHash {
		t.Fatal("artifact differs from source")
	}
	if info, err := os.Stat(run.ArtifactPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("artifact mode is not 0444: %v %v", info, err)
	}

	rep, err := report.Build(ctx, item.store, runID, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Findings == 0 {
		t.Fatal("expected findings")
	}
	if !rep.Summary.AnalysisComplete || !rep.Summary.PipelineComplete {
		t.Fatalf("unexpected completeness: %+v", rep.Summary)
	}
	if !rep.Original.Unmodified || rep.Original.SHA256 != beforeHash || rep.Original.ArtifactMode != "0444" {
		t.Fatalf("original summary=%+v", rep.Original)
	}
	if len(rep.Checkpoints) != 3 || len(rep.Anchors) != 3 {
		t.Fatalf("checkpoints=%d anchors=%d", len(rep.Checkpoints), len(rep.Anchors))
	}
	foundCritical := false
	foundResumeComparison := false
	for _, finding := range rep.Findings {
		if finding.ObservedAt == "" {
			t.Fatalf("finding %d has no observed_at", finding.Ordinal)
		}
		if finding.RawSHA256 == "" || finding.RawExcerpt == "" {
			t.Fatalf("finding %d lost raw evidence", finding.Ordinal)
		}
		if finding.Code == "container_socket_mount" && finding.Severity == "critical" {
			foundCritical = true
		}
	}
	for _, comparison := range rep.Comparisons {
		if comparison.Scope == "resume-replay:stage:1" && comparison.Equal {
			foundResumeComparison = true
		}
	}
	if !foundCritical {
		t.Fatal("missing critical docker socket finding")
	}
	if !foundResumeComparison {
		t.Fatal("missing resume replay comparison")
	}
}

func TestResourceShortageDegradesWithEvidence(t *testing.T) {
	ctx := context.Background()
	limits := audit.DefaultLimits()
	limits.MaxScanBytes = 420
	limits.MaxRecords = 2
	item := newFixture(t, testCapture, limits)
	runID, err := item.store.ResolveRunID(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Process(ctx, item.store, runID, Options{}, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "degraded" || !result.Degraded {
		t.Fatalf("expected degraded result, got %+v", result)
	}
	if result.FinalDigest == "" {
		t.Fatal("degraded run still needs a final digest")
	}
	evidence, err := item.store.GetEvidence(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, item := range evidence {
		kinds[item.Kind] = true
		if item.CapturedAt == "" {
			t.Fatalf("evidence %s has no timestamp", item.Kind)
		}
	}
	if !kinds["resource_scan_budget"] || !kinds["resource_record_quota"] {
		t.Fatalf("missing degradation evidence: %+v", kinds)
	}
	rep, err := report.Build(ctx, item.store, runID, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.AnalysisComplete || !rep.Summary.PipelineComplete || !rep.Summary.Degraded {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}
	if len(rep.Checkpoints) != 3 || rep.Checkpoints[2].EndOffset > limits.MaxScanBytes {
		t.Fatalf("checkpoint offsets=%+v", rep.Checkpoints)
	}
	verified, err := Verify(ctx, item.store, runID, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Equal {
		t.Fatalf("degraded replay mismatch: %+v", verified)
	}
}

func TestAnchorFallbackIsRecorded(t *testing.T) {
	ctx := context.Background()
	input := `100 1 0:1 / /mnt rw - tmpfs tmpfs rw
101 1 0:2 / /data ro - tmpfs tmpfs ro
`
	item := newFixture(t, input, audit.DefaultLimits())
	runID, err := item.store.ResolveRunID(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := item.store.GetAnchors(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if anchors[0].Explicit || anchors[1].Explicit || anchors[2].Explicit {
		t.Fatal("expected synthesized anchors")
	}
	result, err := Process(ctx, item.store, runID, Options{}, item.clock)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "degraded" {
		t.Fatalf("status=%s want degraded fallback", result.Status)
	}
	evidence, err := item.store.GetEvidence(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsKind(evidence, "anchor_fallback") {
		t.Fatal("anchor fallback evidence missing")
	}
}

func TestTamperedEvidenceRowsFailClosed(t *testing.T) {
	ctx := context.Background()
	item := newFixture(t, testCapture, audit.DefaultLimits())
	runID, err := item.store.ResolveRunID(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Process(ctx, item.store, runID, Options{PauseAfter: 2}, item.clock); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", item.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `
UPDATE findings SET detail = 'tampered'
WHERE ordinal = (SELECT MIN(ordinal) FROM findings WHERE stage = 2)`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Process(ctx, item.store, runID, Options{}, item.clock); err == nil ||
		!strings.Contains(err.Error(), "replay differs") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
	run, err := item.store.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "integrity_error" {
		t.Fatalf("status=%s want integrity_error", run.Status)
	}
	evidence, err := item.store.GetEvidence(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsKind(evidence, "integrity_mismatch") {
		t.Fatal("integrity evidence missing")
	}
}

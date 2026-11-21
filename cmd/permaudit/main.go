package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"permaudit/internal/audit"
	"permaudit/internal/store"
)

func nowTS() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00") }

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: permaudit <run|report|compare|verify|snapshot|check-original> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "compare":
		cmdCompare(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "snapshot":
		cmdSnapshot(os.Args[2:])
	case "check-original":
		cmdCheckOriginal(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	db := fs.String("db", "artifacts/audit.db", "SQLite database path")
	image := fs.String("image", "artifacts/image.tar", "container layer tar")
	runID := fs.String("run-id", "", "run identifier (required)")
	checkpointEvery := fs.Int("checkpoint-every", 1, "entries between checkpoints")
	pauseAfter := fs.Int64("pause-after", 0, "pause after N new entries (0=never)")
	memBudget := fs.Int64("mem-budget", 1<<62, "content-hash budget in bytes")
	maxEntries := fs.Int64("max-entries", 0, "hard cap on entries (0=unlimited)")
	fs.Parse(args)
	if *runID == "" {
		die(fmt.Errorf("--run-id is required"))
	}

	sha, err := sha256File(*image)
	if err != nil {
		die(err)
	}
	st, err := store.Open(*db)
	if err != nil {
		die(err)
	}
	defer st.Close()

	params := audit.Params{
		RunID:           *runID,
		ImagePath:       *image,
		CheckpointEvery: *checkpointEvery,
		PauseAfter:      *pauseAfter,
		MemBudgetBytes:  *memBudget,
		MaxEntries:      *maxEntries,
	}
	pj, _ := json.Marshal(params)
	if err := st.CreateRun(*runID, *image, sha, string(pj), nowTS()); err != nil {
		die(err)
	}
	res, err := audit.NewScanner(st, params).Run()
	if err != nil {
		die(err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if res.Paused {
		os.Exit(3) // distinct code: paused, resumable
	}
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	db := fs.String("db", "artifacts/audit.db", "SQLite database path")
	runID := fs.String("run-id", "", "run identifier (required)")
	fs.Parse(args)
	st, err := store.Open(*db)
	if err != nil {
		die(err)
	}
	defer st.Close()
	findings, err := st.Findings(*runID)
	if err != nil {
		die(err)
	}
	fmt.Printf("run=%s findings=%d\n", *runID, len(findings))
	for _, f := range findings {
		fmt.Printf("  ts=%s offset=%-8d %-28s %-10s mode=%#o %s\n",
			f.TS, f.HeaderOffset, f.Path, f.Rule, f.Mode, f.Severity)
	}
	events, err := st.Events(*runID)
	if err != nil {
		die(err)
	}
	fmt.Printf("events=%d\n", len(events))
	for _, e := range events {
		fmt.Printf("  ts=%s offset=%-8d %-8s %s\n", e.TS, e.Offset, e.Kind, e.Detail)
	}
}

func cmdCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	db := fs.String("db", "artifacts/audit.db", "SQLite database path")
	a := fs.String("a", "", "baseline run id")
	b := fs.String("b", "", "candidate run id")
	fs.Parse(args)
	st, err := store.Open(*db)
	if err != nil {
		die(err)
	}
	defer st.Close()
	fa, err := st.Findings(*a)
	if err != nil {
		die(err)
	}
	fb, err := st.Findings(*b)
	if err != nil {
		die(err)
	}
	key := func(f store.FindingRow) string {
		return fmt.Sprintf("%s|%s|%o|%d|%d|%d", f.Path, f.Rule, f.Mode, f.UID, f.GID, f.HeaderOffset)
	}
	ma := map[string]int{}
	for _, f := range fa {
		ma[key(f)]++
	}
	mb := map[string]int{}
	for _, f := range fb {
		mb[key(f)]++
	}
	diff := 0
	for k, n := range ma {
		if mb[k] != n {
			fmt.Printf("  MISMATCH a=%d b=%d %s\n", n, mb[k], k)
			diff++
		}
	}
	for k, n := range mb {
		if ma[k] != n {
			fmt.Printf("  MISMATCH a=%d b=%d %s\n", ma[k], n, k)
			diff++
		}
	}
	if diff > 0 {
		fmt.Printf("compare %s vs %s: FAILED (%d differences)\n", *a, *b, diff)
		os.Exit(1)
	}
	fmt.Printf("compare %s vs %s: OK (%d findings identical)\n", *a, *b, len(fa))
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	db := fs.String("db", "artifacts/audit.db", "SQLite database path")
	image := fs.String("image", "artifacts/image.tar", "container layer tar")
	runID := fs.String("run-id", "", "run identifier (required)")
	fs.Parse(args)
	st, err := store.Open(*db)
	if err != nil {
		die(err)
	}
	defer st.Close()
	findings, err := st.Findings(*runID)
	if err != nil {
		die(err)
	}
	f, err := os.Open(*image)
	if err != nil {
		die(err)
	}
	defer f.Close()
	bad := 0
	for _, fd := range findings {
		name, err := readTarNameAt(f, fd.HeaderOffset)
		if err != nil || name != fd.Path {
			fmt.Printf("  BAD offset=%d path=%s got=%q err=%v\n", fd.HeaderOffset, fd.Path, name, err)
			bad++
		}
	}
	if bad > 0 {
		fmt.Printf("verify %s: FAILED (%d/%d bad offsets)\n", *runID, bad, len(findings))
		os.Exit(1)
	}
	fmt.Printf("verify %s: OK (%d raw offsets re-validated against %s)\n", *runID, len(findings), *image)
}

// readTarNameAt reads the entry name directly from the raw header block at
// the given byte offset, without going through archive/tar.
func readTarNameAt(r io.ReaderAt, offset int64) (string, error) {
	buf := make([]byte, 512)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", err
	}
	return audit.HeaderName(buf)
}

func cmdSnapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	image := fs.String("image", "artifacts/image.tar", "source image")
	dir := fs.String("dir", "artifacts/original", "pristine copy directory")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		die(err)
	}
	sha, err := sha256File(*image)
	if err != nil {
		die(err)
	}
	dst := filepath.Join(*dir, sha+".tar")
	src, err := os.Open(*image)
	if err != nil {
		die(err)
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		die(err)
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		die(err)
	}
	out.Close()
	manifest := fmt.Sprintf("sha256=%s\nfile=%s\nsnapshotted_ts=%s\n", sha, dst, nowTS())
	if err := os.WriteFile(filepath.Join(*dir, "MANIFEST"), []byte(manifest), 0o444); err != nil {
		die(err)
	}
	fmt.Printf("snapshot: %s sha256=%s ts=%s\n", dst, sha, nowTS())
}

func cmdCheckOriginal(args []string) {
	fs := flag.NewFlagSet("check-original", flag.ExitOnError)
	dir := fs.String("dir", "artifacts/original", "pristine copy directory")
	fs.Parse(args)
	data, err := os.ReadFile(filepath.Join(*dir, "MANIFEST"))
	if err != nil {
		die(err)
	}
	var sha, file string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "sha256=") {
			sha = strings.TrimPrefix(line, "sha256=")
		}
		if strings.HasPrefix(line, "file=") {
			file = strings.TrimPrefix(line, "file=")
		}
	}
	got, err := sha256File(file)
	if err != nil {
		die(err)
	}
	if got != sha {
		fmt.Printf("check-original: FAILED original modified (want %s got %s) ts=%s\n", sha, got, nowTS())
		os.Exit(1)
	}
	fmt.Printf("check-original: OK %s untouched sha256=%s ts=%s\n", file, sha, nowTS())
}

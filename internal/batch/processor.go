// Package batch drives the reviewable pipeline: each snapshot line is
// depth-validated, normalized and judged; failures are captured as
// evidence and processing continues with the remaining objects.
package batch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"jsondepth-review/internal/depthjson"
	"jsondepth-review/internal/evidence"
	"jsondepth-review/internal/record"
)

// headLen caps how many bytes of the raw input are kept verbatim in
// the evidence row. The full input is still pinned by its sha256.
const headLen = 160

// Processor runs one snapshot at a time and records evidence.
type Processor struct {
	Store    *evidence.Store
	MaxDepth int
	Logger   *log.Logger // receives the same lines that are stored as evidence

	quarantineDir string
}

// New creates a Processor with a temporary quarantine directory. The
// directory holds full copies of rejected inputs while the run is in
// progress and is removed by Close.
func New(store *evidence.Store, maxDepth int, logger *log.Logger) (*Processor, error) {
	dir, err := os.MkdirTemp("", "jsondepth-quarantine-*")
	if err != nil {
		return nil, err
	}
	return &Processor{Store: store, MaxDepth: maxDepth, Logger: logger, quarantineDir: dir}, nil
}

// QuarantineDir exposes the temp directory so callers can verify cleanup.
func (p *Processor) QuarantineDir() string { return p.quarantineDir }

// Close removes all temporary state. Safe to call via defer.
func (p *Processor) Close() error {
	if p.quarantineDir == "" {
		return nil
	}
	err := os.RemoveAll(p.quarantineDir)
	p.quarantineDir = ""
	return err
}

// Summary tallies one snapshot run.
type Summary struct {
	Total   int
	Allowed int
	Denied  int
}

// ProcessFile consumes a JSONL snapshot. A failure on one line never
// stops the run: it is logged, quarantined, evidenced, and the loop
// continues with the remaining objects.
func (p *Processor) ProcessFile(ctx context.Context, snapshot, path string) (Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return Summary{}, err
	}
	defer f.Close()
	return p.Process(ctx, snapshot, f)
}

// Process consumes JSONL from r.
func (p *Processor) Process(ctx context.Context, snapshot string, r io.Reader) (Summary, error) {
	var sum Summary
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		sum.Total++
		entry := p.handleLine(snapshot, lineNo, raw)
		if entry.Decision == string(record.Allow) {
			sum.Allowed++
		} else {
			sum.Denied++
		}
		if err := p.Store.Add(ctx, entry); err != nil {
			return sum, fmt.Errorf("persist evidence line %d: %w", lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return sum, fmt.Errorf("read snapshot: %w", err)
	}
	return sum, nil
}

// handleLine runs the full chain for one object and mirrors every log
// line both to the logger and into the evidence row.
func (p *Processor) handleLine(snapshot string, lineNo int, raw []byte) (e evidence.Entry) {
	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(&logBuf, "%s\n", msg)
		if p.Logger != nil {
			p.Logger.Printf("[%s:%d] %s", snapshot, lineNo, msg)
		}
	}

	sum := sha256.Sum256(raw)
	e = evidence.Entry{
		Snapshot:  snapshot,
		LineNo:    lineNo,
		Format:    record.FormatUnknown.String(),
		InputHash: hex.EncodeToString(sum[:]),
		InputHead: head(raw),
		InputLen:  len(raw),
		Trigger:   string(depthjson.KindOK),
		Location:  "-",
		Decision:  string(record.Allow),
		CreatedAt: time.Now(),
	}
	defer func() { e.LogExcerpt = strings.TrimRight(logBuf.String(), "\n") }()

	logf("received %d bytes sha256=%s", len(raw), e.InputHash[:16])

	if derr := depthjson.Validate(raw, p.MaxDepth); derr != nil {
		e.Trigger = string(derr.Kind)
		e.Location = derr.Location()
		e.Decision = string(record.DenyUnparseable)
		logf("TRIGGER %s: %s", derr.Kind, derr.Location())
		q := p.quarantine(snapshot, lineNo, raw)
		logf("decision=%s quarantined=%s", e.Decision, q)
		return e
	}

	rec, err := record.Parse(raw)
	if err != nil {
		e.Trigger = string(depthjson.KindSyntax)
		e.Location = "schema"
		e.Decision = string(record.DenyUnparseable)
		logf("TRIGGER schema: %v", err)
		q := p.quarantine(snapshot, lineNo, raw)
		logf("decision=%s quarantined=%s", e.Decision, q)
		return e
	}

	e.RecordID = rec.ID
	e.Format = rec.Format.String()
	decision := record.Judge(rec)
	e.Decision = string(decision)
	logf("record=%s format=%s subject=%s action=%s decision=%s",
		rec.ID, rec.Format, rec.Subject, rec.Action, decision)
	return e
}

// quarantine keeps a full copy of a rejected input in the temp dir for
// the duration of the run.
func (p *Processor) quarantine(snapshot string, lineNo int, raw []byte) string {
	if p.quarantineDir == "" {
		return "(unavailable)"
	}
	name := fmt.Sprintf("%s-line%d.bin", snapshot, lineNo)
	path := filepath.Join(p.quarantineDir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "(failed: " + err.Error() + ")"
	}
	return path
}

func head(raw []byte) string {
	if len(raw) > headLen {
		return string(raw[:headLen]) + "..."
	}
	return string(raw)
}

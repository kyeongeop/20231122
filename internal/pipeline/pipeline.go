package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/example/jwtconf/internal/evidence"
	"github.com/example/jwtconf/internal/ext"
	"github.com/example/jwtconf/internal/jwt"
)

// Object is one attack/benign input to reproduce against.
type Object struct {
	Name  string
	Token string
}

// Result summarizes the run for review.
type Result struct {
	Records []evidence.Record
	Errors  []error
	TmpDir  string
	Cleaned bool
}

// logBuffer captures log lines so they can be correlated into evidence.
type logBuffer struct{ lines []evidence.LogRef }

func (b *logBuffer) add(level, msg string) {
	b.lines = append(b.lines, evidence.LogRef{Seq: len(b.lines) + 1, Level: level, Message: msg})
}

// caller reports the file:line of the permission decision site.
func caller(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown:0"
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

// Run executes the reproduction over all objects. A failure on one object
// is recorded and processing continues with the remaining objects. Temporary
// state is cleaned up when the run ends.
func Run(objects []Object, store *evidence.Store, workDir string, pub any) (*Result, error) {
	tmp, err := os.MkdirTemp(workDir, "jwtconf-tmp-*")
	if err != nil {
		return nil, err
	}
	res := &Result{TmpDir: tmp}
	defer func() {
		if err := os.RemoveAll(tmp); err == nil {
			res.Cleaned = true
		}
	}()

	legacy, fixed, err := verifiers(pub)
	if err != nil {
		return nil, err
	}

	for i, obj := range objects {
		rec, err := process(obj, legacy, fixed, i)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("object %s: %w", obj.Name, err))
			continue
		}
		// Legacy objects are stored in the old v1 format, the rest in v2,
		// so the evidence base always exercises both readers.
		format := evidence.FormatV2
		if strings.HasSuffix(obj.Name, "-legacy") {
			format = evidence.FormatV1
		}
		if err := store.Save(rec, format); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("object %s: save: %w", obj.Name, err))
			continue
		}
		res.Records = append(res.Records, rec)
	}
	return res, nil
}

// process reproduces one object under both extension snapshots and builds
// the correlated evidence record.
func process(obj Object, legacy, fixed jwt.Verifier, seq int) (rec evidence.Record, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	buf := &logBuffer{}
	sum := sha256.Sum256([]byte(obj.Token))
	rec = evidence.Record{
		ID:         fmt.Sprintf("ev-%04d", seq+1),
		Object:     obj.Name,
		AttackHash: hex.EncodeToString(sum[:]),
		CreatedAt:  time.Now().UTC(),
	}
	buf.add("info", "received object "+obj.Name)

	// Snapshot the unknown extension in both versions around the decision.
	p1 := ext.NewV1()
	p2 := ext.NewV2()
	snapBefore1 := p1.Snap()
	snapBefore2 := p2.Snap()

	tok, perr := jwt.Parse(obj.Token)
	if perr != nil {
		buf.add("error", "parse failed: "+perr.Error())
		rec.Decision = "error"
		rec.Trigger = caller(0)
		rec.Reason = perr.Error()
		rec.Logs = buf.lines
		rec.Snaps = []ext.Snapshot{snapBefore1, snapBefore2}
		return rec, nil
	}
	buf.add("info", "parsed token alg="+tok.Header.Alg)

	// Legacy path (v1 snapshot): vulnerable decision point.
	p1.Note("verify alg=%s via %s", tok.Header.Alg, legacy.Name())
	legacyErr := legacy.Verify(tok)
	buf.add("audit", fmt.Sprintf("legacy decision err=%v", legacyErr))

	// Fixed path (v2 snapshot): the permission decision under review.
	p2.Note("verify alg=%s via %s", tok.Header.Alg, fixed.Name())
	fixedErr := fixed.Verify(tok)
	trigger := caller(0) // permission decision site
	buf.add("audit", fmt.Sprintf("fixed decision err=%v", fixedErr))

	switch {
	case fixedErr == nil:
		rec.Decision = "allow"
		rec.Reason = "signature valid under pinned RS256"
	case legacyErr == nil && fixedErr != nil:
		rec.Decision = "deny"
		rec.Reason = "alg-confusion accepted by legacy, rejected by fixed"
		buf.add("critical", "algorithm confusion reproduced: legacy would allow")
	default:
		rec.Decision = "deny"
		rec.Reason = fixedErr.Error()
	}

	rec.Trigger = trigger
	rec.Logs = buf.lines
	rec.Snaps = []ext.Snapshot{snapBefore1, snapBefore2, p1.Snap(), p2.Snap()}
	return rec, nil
}

// LogSummary mirrors key evidence to the standard logger for the reviewer.
func LogSummary(res *Result) {
	for _, r := range res.Records {
		log.Printf("evidence %s object=%s decision=%s trigger=%s", r.ID, r.Object, r.Decision, r.Trigger)
	}
	for _, e := range res.Errors {
		log.Printf("object error (continued): %v", e)
	}
}

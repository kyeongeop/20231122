package audit

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"permaudit/internal/store"
)

// Params are the (possibly extreme) parameters of one audit run.
type Params struct {
	RunID           string
	ImagePath       string
	CheckpointEvery int   // entries between checkpoints; 1 = every entry
	PauseAfter      int64 // pause after this many new entries this invocation; 0 = never
	MemBudgetBytes  int64 // content-hash budget; exhaustion triggers degraded mode
	MaxEntries      int64 // hard cap on total entries; 0 = unlimited
}

// Scanner performs a pausable, resumable permission audit over a tar layer.
type Scanner struct {
	st *store.Store
	p  Params
}

// NewScanner builds a Scanner.
func NewScanner(st *store.Store, p Params) *Scanner { return &Scanner{st: st, p: p} }

func nowTS() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00") }

// Result summarizes one invocation.
type Result struct {
	Completed    bool
	Paused       bool
	Degraded     bool
	EntriesTotal int64
	Findings     int64
	NextOffset   int64
}

// Run executes the scan from the last checkpoint (or offset 0) until
// completion, pause, or resource exhaustion.
func (s *Scanner) Run() (Result, error) {
	var res Result
	cp, err := s.st.LatestCheckpoint(s.p.RunID)
	if err != nil {
		return res, fmt.Errorf("load checkpoint: %w", err)
	}
	var (
		offset      int64
		entriesDone int64
		findingsSeq int64
		cpSeq       int64
		degraded    bool
		stateHash   = sha256.New()
	)
	if cp != nil {
		offset = cp.NextOffset
		entriesDone = cp.EntriesDone
		findingsSeq = cp.FindingsDone
		cpSeq = cp.Seq + 1
		degraded = cp.Degraded
		// state hash continuity is anchored in the checkpoint row itself;
		// a resumed run re-seeds from the stored hash.
		stateHash.Write([]byte(cp.StateHash))
	}

	f, err := os.Open(s.p.ImagePath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return res, fmt.Errorf("seek to %d: %w", offset, err)
	}

	eventSeq, err := s.st.NextEventSeq(s.p.RunID)
	if err != nil {
		return res, err
	}
	logEvent := func(kind, detail string, off int64) {
		_ = s.st.LogEvent(s.p.RunID, eventSeq, kind, detail, off, nowTS())
		eventSeq++
	}
	if cp != nil {
		logEvent("resume", fmt.Sprintf("resumed at offset %d (entries=%d)", offset, entriesDone), offset)
	}

	counter := &countingReader{r: f, n: offset}
	tr := tar.NewReader(counter)
	budget := s.p.MemBudgetBytes
	var processedThisCall int64
	nextOff := offset // aligned offset of the next unread header

	saveCheckpoint := func() error {
		c := store.Checkpoint{
			Seq:          cpSeq,
			NextOffset:   nextOff,
			EntriesDone:  entriesDone,
			FindingsDone: findingsSeq,
			Degraded:     degraded,
			StateHash:    hex.EncodeToString(stateHash.Sum(nil)),
			TS:           nowTS(),
		}
		if err := s.st.SaveCheckpoint(s.p.RunID, c); err != nil {
			return err
		}
		cpSeq++
		return nil
	}

	for {
		if s.p.MaxEntries > 0 && entriesDone >= s.p.MaxEntries {
			logEvent("degrade", fmt.Sprintf("max-entries cap %d reached; stopping early", s.p.MaxEntries), nextOff)
			if err := saveCheckpoint(); err != nil {
				return res, err
			}
			res.Degraded = true
			break
		}
		if s.p.PauseAfter > 0 && processedThisCall >= s.p.PauseAfter {
			if err := saveCheckpoint(); err != nil {
				return res, err
			}
			logEvent("pause", fmt.Sprintf("paused at offset %d after %d entries", nextOff, processedThisCall), nextOff)
			res.Paused = true
			res.EntriesTotal = entriesDone
			res.Findings = findingsSeq
			res.NextOffset = nextOff
			res.Degraded = degraded
			return res, nil
		}

		// tar.Reader skips data padding lazily inside Next(), so the raw
		// consumed count can sit mid-padding. The true header offset is the
		// next 512-byte boundary.
		hdrOffset := (counter.n + 511) / 512 * 512
		hdr, err := tr.Next()
		if err == io.EOF {
			res.Completed = true
			break
		}
		if err != nil {
			return res, fmt.Errorf("tar header at offset %d: %w", hdrOffset, err)
		}
		entriesDone++
		processedThisCall++

		isDir := hdr.Typeflag == tar.TypeDir
		for _, fd := range ClassifyMode(hdr.Name, uint32(hdr.Mode), hdr.Uid, hdr.Gid, isDir) {
			findingsSeq++
			row := store.FindingRow{
				Seq:          findingsSeq,
				Path:         fd.Path,
				Mode:         int64(fd.Mode),
				UID:          int64(fd.UID),
				GID:          int64(fd.GID),
				Size:         hdr.Size,
				HeaderOffset: hdrOffset,
				Rule:         fd.Rule,
				Severity:     fd.Severity,
				Degraded:     degraded,
				TS:           nowTS(),
			}
			if err := s.st.InsertFinding(s.p.RunID, row); err != nil {
				return res, err
			}
			fmt.Fprintf(stateHash, "%s|%o|%s\n", fd.Path, fd.Mode, fd.Rule)
		}

		// Consume entry content; hashing it while budget allows.
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			if !degraded && budget >= hdr.Size {
				if _, err := io.CopyN(hashWriter{stateHash}, tr, hdr.Size); err != nil {
					return res, fmt.Errorf("hash content of %s: %w", hdr.Name, err)
				}
				budget -= hdr.Size
			} else {
				if !degraded {
					degraded = true
					logEvent("degrade", fmt.Sprintf("mem budget exhausted at %q; switching to metadata-only", hdr.Name), hdrOffset)
				}
				if _, err := io.Copy(io.Discard, tr); err != nil {
					return res, fmt.Errorf("skip content of %s: %w", hdr.Name, err)
				}
			}
		}

		// Aligned offset of the next header; used as the resume point so a
		// resumed run can seek there directly with a fresh tar.Reader.
		nextOff = hdrOffset + 512 + (hdr.Size+511)/512*512

		if s.p.CheckpointEvery > 0 && processedThisCall%int64(s.p.CheckpointEvery) == 0 {
			if err := saveCheckpoint(); err != nil {
				return res, err
			}
		}
	}

	if err := saveCheckpoint(); err != nil {
		return res, err
	}
	status := "completed"
	if res.Degraded {
		status = "completed_degraded"
	}
	logEvent("complete", fmt.Sprintf("run finished: entries=%d findings=%d degraded=%v", entriesDone, findingsSeq, degraded), counter.n)
	if err := s.st.SetRunStatus(s.p.RunID, status, nowTS()); err != nil {
		return res, err
	}
	res.EntriesTotal = entriesDone
	res.Findings = findingsSeq
	res.NextOffset = nextOff
	res.Degraded = degraded
	return res, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type hashWriter struct{ h hash.Hash }

func (w hashWriter) Write(p []byte) (int, error) { return w.h.Write(p) }

package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"unicodebypass/internal/filter"
	"unicodebypass/internal/store"
)

// Config tunes the pausable processing flow.
type Config struct {
	BatchSize  int           // items per checkpoint transaction
	PauseAfter int           // pause (and exit) after this many items; 0 = never
	Deadline   time.Duration // wall-clock budget for one session
	DegradeLen int           // names longer than this use the degraded path
	Boundary   int           // filename-length boundary to sample (e.g. 255)
}

// DefaultConfig returns sane defaults for the demo corpus.
func DefaultConfig() Config {
	return Config{
		BatchSize:  16,
		PauseAfter: 0,
		Deadline:   5 * time.Minute,
		DegradeLen: 4096,
		Boundary:   255,
	}
}

// Processor runs the corpus through the filter with checkpointing.
type Processor struct {
	db       *store.DB
	cfg      Config
	items    []Item
	RunID    int64
	Segment  string // "pre-pause" or "post-resume"
	offset   int    // next item to process
	digest   [sha256.Size]byte
	lastHash string
	degraded bool

	// boundary sample candidates, flushed at each checkpoint
	before, after *boundarySample
}

type boundarySample struct {
	item Item
	v    filter.Verdict
}

// Checkpoint is the resumable intermediate state.
type Checkpoint struct {
	Offset    int
	Processed int
	Findings  int
	Digest    string
	LastHash  string
	Degraded  bool
}

func verdictHash(it Item, v filter.Verdict) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%q|%t|%t|%t",
		it.ID, it.Name, v.ValidatorOK, v.OracleDanger, v.Degraded)))
	return hex.EncodeToString(h[:])
}

// LatestCheckpoint returns the most recent checkpoint across runs.
func LatestCheckpoint(db *store.DB) (*Checkpoint, int64, error) {
	st, err := db.Prepare(`SELECT run_id, offset, processed, findings, digest, last_hash, degraded
		FROM checkpoints ORDER BY rowid DESC LIMIT 1`)
	if err != nil {
		return nil, 0, err
	}
	defer st.Close()
	row, err := st.QueryRow(7)
	if err != nil || row == nil {
		return nil, 0, err
	}
	var runID int64
	fmt.Sscan(row[0], &runID)
	cp := &Checkpoint{}
	fmt.Sscan(row[1], &cp.Offset)
	fmt.Sscan(row[2], &cp.Processed)
	fmt.Sscan(row[3], &cp.Findings)
	cp.Digest = row[4]
	cp.LastHash = row[5]
	cp.Degraded = row[6] == "1"
	return cp, runID, nil
}

// NewProcessor starts a fresh run (resume=false) or resumes from the
// latest checkpoint (resume=true). On resume it recomputes the verdict
// hash of the last pre-pause item and compares it with the checkpoint
// to prove the intermediate state is intact.
func NewProcessor(db *store.DB, cfg Config, items []Item, resume bool) (*Processor, string, error) {
	p := &Processor{db: db, cfg: cfg, items: items, Segment: "pre-pause"}
	if !resume {
		st, err := db.Prepare(`INSERT INTO runs(started_at, note) VALUES(?, ?)`)
		if err != nil {
			return nil, "", err
		}
		st.BindText(1, time.Now().UTC().Format(time.RFC3339))
		st.BindText(2, "unicode-bypass pausable run")
		if err := st.Exec(); err != nil {
			st.Close()
			return nil, "", err
		}
		st.Close()
		id, err := lastInsertID(db)
		if err != nil {
			return nil, "", err
		}
		p.RunID = id
		return p, "fresh run started", nil
	}
	cp, runID, err := LatestCheckpoint(db)
	if err != nil {
		return nil, "", err
	}
	if cp == nil {
		return nil, "", fmt.Errorf("no checkpoint to resume from")
	}
	p.RunID = runID
	p.Segment = "post-resume"
	p.offset = cp.Offset
	p.degraded = cp.Degraded
	d, err := hex.DecodeString(cp.Digest)
	if err != nil || len(d) != sha256.Size {
		return nil, "", fmt.Errorf("corrupt checkpoint digest")
	}
	copy(p.digest[:], d)
	// Integrity check: re-verify the last processed item.
	if cp.Offset > 0 && cp.Offset <= len(items) {
		prev := items[cp.Offset-1]
		degraded := cp.Degraded || len(prev.Name) >= cfg.DegradeLen
		got := verdictHash(prev, classify(prev, degraded))
		if got != cp.LastHash {
			return nil, "", fmt.Errorf("checkpoint integrity mismatch at item %d: state drift detected", prev.ID)
		}
	}
	p.lastHash = cp.LastHash
	return p, fmt.Sprintf("resumed at offset %d (integrity OK)", cp.Offset), nil
}

func lastInsertID(db *store.DB) (int64, error) {
	st, err := db.Prepare(`SELECT last_insert_rowid()`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	return st.QueryInt()
}

// classify picks the full or degraded path based on resource pressure.
func classify(it Item, degraded bool) filter.Verdict {
	if degraded {
		return filter.ClassifyDegraded(it.Name)
	}
	return filter.Classify(it.Name)
}

// Result summarizes one processing session.
type Result struct {
	Paused    bool
	Processed int
	Findings  int
	Bypasses  int
	Degraded  bool
	Done      bool
}

// Process runs items from the current offset until completion, pause
// request, or deadline. Every batch commits a checkpoint transaction,
// so an interrupted session loses at most one batch.
func (p *Processor) Process() (Result, error) {
	var res Result
	deadline := time.Now().Add(p.cfg.Deadline)
	processedThisSession := 0

	for p.offset < len(p.items) {
		end := p.offset + p.cfg.BatchSize
		if end > len(p.items) {
			end = len(p.items)
		}
		if err := p.db.BeginTx(); err != nil {
			return res, err
		}
		for _, it := range p.items[p.offset:end] {
			// Resource guard. Oversize names degrade only that item
			// (cheap path); an expired deadline degrades the rest of
			// the session (sticky, persisted in the checkpoint).
			itemDegraded := p.degraded
			if len(it.Name) >= p.cfg.DegradeLen {
				itemDegraded = true
				if err := p.recordDegradation(it, "oversize-name"); err != nil {
					p.db.Rollback()
					return res, err
				}
			} else if !p.degraded && time.Now().After(deadline) {
				p.degraded = true
				itemDegraded = true
				if err := p.recordDegradation(it, "deadline-exceeded"); err != nil {
					p.db.Rollback()
					return res, err
				}
			}
			v := classify(it, itemDegraded)
			p.lastHash = verdictHash(it, v)
			p.digest = sha256.Sum256(append(p.digest[:], []byte(p.lastHash)...))
			if v.OracleDanger {
				if err := p.recordFinding(it, v); err != nil {
					p.db.Rollback()
					return res, err
				}
				res.Findings++
				if v.Bypass() {
					res.Bypasses++
				}
			}
			p.trackBoundary(it, v)
			processedThisSession++
		}
		p.offset = end
		if err := p.flushCheckpoint(res.Findings); err != nil {
			p.db.Rollback()
			return res, err
		}
		if err := p.db.Commit(); err != nil {
			return res, err
		}
		res.Processed += processedThisSession
		processedThisSession = 0
		if p.cfg.PauseAfter > 0 && res.Processed >= p.cfg.PauseAfter && p.offset < len(p.items) {
			res.Paused = true
			res.Degraded = p.degraded
			return res, p.flushBoundary()
		}
	}
	res.Degraded = p.degraded
	res.Done = true
	return res, p.flushBoundary()
}

func (p *Processor) recordFinding(it Item, v filter.Verdict) error {
	st, err := p.db.Prepare(`INSERT INTO findings
		(run_id, item_id, name, len, validator_ok, oracle_danger, bypass, degraded, segment)
		VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	st.BindInt(1, p.RunID)
	st.BindInt(2, int64(it.ID))
	st.BindText(3, it.Name)
	st.BindInt(4, int64(len(it.Name)))
	st.BindInt(5, b2i(v.ValidatorOK))
	st.BindInt(6, b2i(v.OracleDanger))
	st.BindInt(7, b2i(v.Bypass()))
	st.BindInt(8, b2i(v.Degraded))
	st.BindText(9, p.Segment)
	return st.Exec()
}

func (p *Processor) recordDegradation(it Item, reason string) error {
	st, err := p.db.Prepare(`INSERT INTO degradations(run_id, item_id, reason, created_at)
		VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	st.BindInt(1, p.RunID)
	st.BindInt(2, int64(it.ID))
	st.BindText(3, reason)
	st.BindText(4, time.Now().UTC().Format(time.RFC3339))
	return st.Exec()
}

// trackBoundary keeps the closest sample on each side of the boundary.
func (p *Processor) trackBoundary(it Item, v filter.Verdict) {
	l := len(it.Name)
	if l <= p.cfg.Boundary {
		if p.before == nil || l > len(p.before.item.Name) {
			p.before = &boundarySample{item: it, v: v}
		}
	} else if p.after == nil || l < len(p.after.item.Name) {
		p.after = &boundarySample{item: it, v: v}
	}
}

// flushCheckpoint writes the checkpoint row. Called inside the batch
// transaction.
func (p *Processor) flushCheckpoint(findings int) error {
	st, err := p.db.Prepare(`INSERT INTO checkpoints
		(run_id, offset, processed, findings, digest, last_hash, degraded, created_at)
		VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	st.BindInt(1, p.RunID)
	st.BindInt(2, int64(p.offset))
	st.BindInt(3, int64(p.offset))
	st.BindInt(4, int64(findings))
	st.BindText(5, hex.EncodeToString(p.digest[:]))
	st.BindText(6, p.lastHash)
	st.BindInt(7, b2i(p.degraded))
	st.BindText(8, time.Now().UTC().Format(time.RFC3339))
	if err := st.Exec(); err != nil {
		st.Close()
		return err
	}
	st.Close()
	return nil
}

// flushBoundary records the single closest sample on each side of the
// boundary observed during this session, so each segment (pre-pause /
// post-resume) yields exactly one "before" and one "after" sample.
func (p *Processor) flushBoundary() error {
	if p.before == nil && p.after == nil {
		return nil
	}
	if err := p.db.BeginTx(); err != nil {
		return err
	}
	for _, s := range []struct {
		side string
		bs   *boundarySample
	}{{"before", p.before}, {"after", p.after}} {
		if s.bs == nil {
			continue
		}
		if err := p.recordBoundary(s.side, *s.bs); err != nil {
			p.db.Rollback()
			return err
		}
	}
	return p.db.Commit()
}

func (p *Processor) recordBoundary(side string, s boundarySample) error {
	st, err := p.db.Prepare(`INSERT INTO boundary_samples
		(run_id, boundary, side, item_id, len, validator_ok, oracle_danger, segment)
		VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	st.BindInt(1, p.RunID)
	st.BindInt(2, int64(p.cfg.Boundary))
	st.BindText(3, side)
	st.BindInt(4, int64(s.item.ID))
	st.BindInt(5, int64(len(s.item.Name)))
	st.BindInt(6, b2i(s.v.ValidatorOK))
	st.BindInt(7, b2i(s.v.OracleDanger))
	st.BindText(8, p.Segment)
	return st.Exec()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

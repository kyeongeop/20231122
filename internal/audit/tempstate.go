package audit

// Temporary staging state lives in a dedicated table for the duration of a
// run and is dropped (and verified gone) when the run finishes.

const tempTable = `_tmp_staging`

func (p *Pipeline) createTempState() error {
	_, err := p.Store.db.Exec(
		`CREATE TABLE IF NOT EXISTS ` + tempTable + ` (
			label TEXT NOT NULL,
			sha256 TEXT NOT NULL
		)`)
	return err
}

func (p *Pipeline) stageTemp(label, sha string) error {
	_, err := p.Store.db.Exec(
		`INSERT INTO `+tempTable+`(label, sha256) VALUES(?,?)`, label, sha)
	return err
}

// cleanupTempState drops the staging table and confirms it is gone.
func (p *Pipeline) cleanupTempState() bool {
	if _, err := p.Store.db.Exec(`DROP TABLE IF EXISTS ` + tempTable); err != nil {
		return false
	}
	var name string
	row := p.Store.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tempTable)
	return row.Scan(&name) != nil // scan must find nothing
}

package main

import (
	"fmt"

	"tve/internal/runner"
	"tve/internal/store"
)

func cmdVerify(args []string) error {
	fs := newFlagSet("verify")
	db := fs.String("db", defDB, "SQLite database path")
	dir := fs.String("dir", defDir, "artifact directory")
	jobID := fs.Int64("job", 0, "job id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	rep, err := runner.Verify(st, *jobID, *dir)
	if err != nil {
		return err
	}
	for _, l := range rep.Lines {
		fmt.Println(l)
	}
	if !rep.OK {
		return fmt.Errorf("acceptance FAILED for job %d", *jobID)
	}
	fmt.Printf("ACCEPTANCE OK job=%d\n", *jobID)
	return nil
}

func cmdEvents(args []string) error {
	fs := newFlagSet("events")
	db := fs.String("db", defDB, "SQLite database path")
	jobID := fs.Int64("job", 0, "job id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.OpenStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	evs, err := st.Events(*jobID)
	if err != nil {
		return err
	}
	fmt.Printf("%-4s %-32s %-18s %-8s %-10s %s\n", "id", "ts_utc", "kind", "record", "raw_offset", "detail")
	for _, e := range evs {
		d := e.Detail
		if len(d) > 60 {
			d = d[:60] + "..."
		}
		fmt.Printf("%-4d %-32s %-18s %-8d %-10d %s\n",
			e.ID, e.TsUTC, e.Kind, e.RecordIndex, e.RawOffset, d)
	}
	cps, err := st.Checkpoints(*jobID)
	if err != nil {
		return err
	}
	fmt.Printf("\n%-4s %-32s %-10s %-10s %-10s\n", "seq", "saved_utc", "next", "processed", "degraded")
	for _, c := range cps {
		fmt.Printf("%-4d %-32s %-10d %-10d %-10d\n",
			c.Seq, c.SavedUTC, c.NextIndex, c.Processed, c.Degraded)
	}
	return nil
}

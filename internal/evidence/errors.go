package evidence

import "errors"

// HardLineLimit 限制单条导出记录的最大行长（4 MiB）。
const HardLineLimit = 4 << 20

var (
	ErrEmptyExport  = errors.New("export stream contains no records")
	ErrHashMismatch = errors.New("record hash mismatch")
)

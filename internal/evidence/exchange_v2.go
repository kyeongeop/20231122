package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"quotabypass/internal/model"
)

const (
	ExportSchema  = "quota-bypass.export/v1"
	GeneratorName = "quotabypass/rebuild"
)

// WriteExportFile 写 evidence.json：schema + generator + 顺序固定的记录数组。
func WriteExportFile(w io.Writer, records []model.Record) error {
	for _, rec := range records {
		if err := VerifyRecord(rec); err != nil {
			return fmt.Errorf("export %s: %w", rec.RunID, err)
		}
	}
	out := model.ExportFile{Schema: ExportSchema, Generator: GeneratorName, Records: records}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// WriteJSONL 写 evidence.jsonl：每行一条完整记录，字段顺序遵循结构体定义。
func WriteJSONL(w io.Writer, records []model.Record) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	for _, rec := range records {
		if err := VerifyRecord(rec); err != nil {
			return err
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ReadJSONL 重载 JSONL，逐行校验指纹与字段顺序。
func ReadJSONL(r io.Reader) ([]model.Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), HardLineLimit)
	var out []model.Record
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("line %d: decode: %w", lineNo, err)
		}
		if err := VerifyRecord(rec); err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNo, rec.RunID, err)
		}
		// 字段顺序复核：重新序列化必须与输入字节一致。
		again, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(again, line) {
			return nil, fmt.Errorf("line %d: field order drift detected", lineNo)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrEmptyExport
	}
	return out, nil
}

// ReadExportFile 重载 evidence.json 并校验全部记录。
func ReadExportFile(r io.Reader) ([]model.Record, error) {
	var file model.ExportFile
	if err := json.NewDecoder(r).Decode(&file); err != nil {
		return nil, fmt.Errorf("decode export file: %w", err)
	}
	if file.Schema != ExportSchema {
		return nil, fmt.Errorf("unexpected schema %q", file.Schema)
	}
	for _, rec := range file.Records {
		if err := VerifyRecord(rec); err != nil {
			return nil, fmt.Errorf("%s: %w", rec.RunID, err)
		}
	}
	return file.Records, nil
}

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"quotabypass/internal/evidence"
	"quotabypass/internal/model"
	"quotabypass/internal/quota"
	"quotabypass/internal/store"
)

func main2() int {
	if len(os.Args) < 2 {
		usageV2()
		return 2
	}
	var err error
	switch os.Args[1] {
	case "rebuild":
		err = cmdRebuild(os.Args[2:])
	case "export":
		err = cmdExportV2(os.Args[2:])
	case "import":
		err = cmdImportV2(os.Args[2:])
	case "verify":
		err = cmdVerifyV2(os.Args[2:])
	case "query":
		err = cmdQueryV2(os.Args[2:])
	case "manifest":
		err = cmdManifestV2(os.Args[2:])
	default:
		usageV2()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "quotabypass: %v\n", err)
		return 1
	}
	return 0
}

func usageV2() {
	fmt.Fprint(os.Stderr, `usage: quotabypass <command> [flags]
  rebuild -db PATH [-out DIR]  重建六个标准场景，写 SQLite 并导出证据
  export  -db PATH -out DIR    从 SQLite 重新导出 evidence.json / evidence.jsonl
  import  -db PATH -in FILE    重载 JSONL，校验哈希与字段顺序后入库
  verify  -db PATH             校验库内全部记录指纹
  query   -db PATH -ordinal N  打印单条记录摘要与关键证据
  manifest -db PATH -out FILE 生成带顺序与哈希的复核清单
`)
}

func rebuildRecords() []model.Record {
	specs := quota.DefaultScenarios()
	records := make([]model.Record, 0, len(specs))
	for i, sc := range specs {
		records = append(records, quota.NewRunner(sc.Mode).Run(sc.Name, i, sc.Raw))
	}
	return records
}

func cmdRebuild(args []string) error {
	fs := flag.NewFlagSet("rebuild", flag.ContinueOnError)
	dbPath := fs.String("db", "artifacts/evidence.sqlite", "SQLite database path")
	outDir := fs.String("out", "artifacts", "export directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}

	st, err := store.OpenV2(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	records := rebuildRecords()
	for _, rec := range records {
		if err := st.Save(rec); err != nil {
			return err
		}
	}
	if err := writeExportsV2(records, *outDir); err != nil {
		return err
	}
	if err := cmdManifestV2([]string{
		"-db", *dbPath,
		"-out", filepath.Join(*outDir, "manifest.json"),
	}); err != nil {
		return err
	}

	for _, rec := range records {
		fmt.Printf("%-28s %-10s allowed=%-2d denied=%-2d bypass=%-5v %s\n",
			rec.Scenario, rec.Mode, rec.Summary.Allowed, rec.Summary.Denied,
			rec.Summary.BypassDetected, rec.RecordSHA256[:16])
	}
	fmt.Printf("database: %s\n", *dbPath)
	return nil
}

func writeExportsV2(records []model.Record, outDir string) error {
	jsonPath := filepath.Join(outDir, "evidence.json")
	jf, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	if err := evidence.WriteExportFile(jf, records); err != nil {
		jf.Close()
		return err
	}
	jf.Close()

	jsonlPath := filepath.Join(outDir, "evidence.jsonl")
	lf, err := os.Create(jsonlPath)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := evidence.WriteJSONL(lf, records); err != nil {
		return err
	}
	fmt.Printf("exported %d records -> %s, %s\n", len(records), jsonPath, jsonlPath)
	return nil
}

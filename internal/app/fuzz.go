package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"serrfix/internal/model"
	"serrfix/internal/store"
)

const fuzzBundleMagic = "SERRFIX-FUZZ-CORPUS/v1\n"

type FuzzOptions struct {
	Runs       int
	MaxSeconds int
	TargetPath string
	DictPath   string
	ClangXX    string
	Build      bool
	MaxSeeds   int
}

type FuzzFile struct {
	Name         string `json:"name"`
	BundleOffset int64  `json:"bundle_offset"`
	Length       int64  `json:"length"`
	SHA256       string `json:"sha256"`
	SampleID     string `json:"sample_id,omitempty"`
}

type FuzzResult struct {
	Schema           string     `json:"schema"`
	StartedAt        string     `json:"started_at"`
	FinishedAt       string     `json:"finished_at"`
	RunDir           string     `json:"run_dir"`
	Target           string     `json:"target"`
	ClangXX          string     `json:"clangxx"`
	SeedCount        int        `json:"seed_count"`
	CorpusFiles      int        `json:"corpus_files"`
	ImportedSamples  int        `json:"imported_samples"`
	MaterialID       string     `json:"material_id"`
	BundlePath       string     `json:"bundle_path"`
	BundleSHA256     string     `json:"bundle_sha256"`
	ManifestPath     string     `json:"manifest_path"`
	LogPath          string     `json:"log_path"`
	LogTail          string     `json:"log_tail"`
	CommandExitError string     `json:"command_exit_error,omitempty"`
	Files            []FuzzFile `json:"files"`
}

type fuzzManifest struct {
	Schema     string     `json:"schema"`
	StartedAt  string     `json:"started_at"`
	FinishedAt string     `json:"finished_at"`
	Command    []string   `json:"command"`
	Target     string     `json:"target"`
	Dictionary string     `json:"dictionary"`
	SeedCount  int        `json:"seed_count"`
	BundlePath string     `json:"bundle_path"`
	BundleSHA  string     `json:"bundle_sha256"`
	Files      []FuzzFile `json:"files"`
}

func (a *App) Fuzz(ctx context.Context, opts FuzzOptions) (FuzzResult, error) {
	if err := a.requireInitialized(); err != nil {
		return FuzzResult{}, err
	}
	if opts.Runs <= 0 {
		opts.Runs = 2000
	}
	if opts.MaxSeconds <= 0 {
		opts.MaxSeconds = 5
	}
	if opts.MaxSeeds <= 0 {
		opts.MaxSeeds = 256
	}
	if opts.TargetPath == "" {
		opts.TargetPath = "fuzz/error_target.cpp"
	}
	if opts.DictPath == "" {
		opts.DictPath = "fuzz/secret.dict"
	}
	if opts.ClangXX == "" {
		opts.ClangXX = os.Getenv("CLANGXX")
	}
	if opts.ClangXX == "" {
		opts.ClangXX = "clang++"
	}
	targetAbs, err := filepath.Abs(opts.TargetPath)
	if err != nil {
		return FuzzResult{}, err
	}
	dictAbs, err := filepath.Abs(opts.DictPath)
	if err != nil {
		return FuzzResult{}, err
	}
	if _, err := os.Stat(targetAbs); err != nil {
		return FuzzResult{}, fmt.Errorf("libFuzzer target %s: %w", targetAbs, err)
	}
	if _, err := os.Stat(dictAbs); err != nil {
		return FuzzResult{}, fmt.Errorf("libFuzzer dictionary %s: %w", dictAbs, err)
	}
	started := a.now()
	result := FuzzResult{
		Schema: "serrfix.fuzz/v1", StartedAt: model.Timestamp(started),
		Target: targetAbs,
	}
	runName := "run-" + started.Format("20060102T150405.000000000Z")
	runDir := filepath.Join(a.WS.FuzzDir(), runName)
	corpusDir := filepath.Join(runDir, "corpus")
	artifactDir := filepath.Join(runDir, "artifacts")
	for _, dir := range []string{corpusDir, artifactDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return result, err
		}
	}
	result.RunDir = a.rel(runDir)
	seedCount, err := a.writeSeeds(corpusDir, opts.MaxSeeds)
	if err != nil {
		return result, err
	}
	result.SeedCount = seedCount

	binary := filepath.Join(a.WS.BinDir(), "error_fuzzer")
	buildCmd := []string{"-std=c++17", "-O1", "-g", "-fsanitize=fuzzer,address",
		"-fno-omit-frame-pointer", "-o", binary, targetAbs}
	if opts.Build || !fileUpToDate(binary, targetAbs) {
		cmd := exec.CommandContext(ctx, opts.ClangXX, buildCmd...)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Run(); err != nil {
			return result, fmt.Errorf("build libFuzzer target with %s: %w\n%s",
				opts.ClangXX, err, tail(output.String(), 3000))
		}
	}
	if _, err := os.Stat(binary); err != nil {
		return result, err
	}
	result.ClangXX = opts.ClangXX
	args := []string{
		fmt.Sprintf("-runs=%d", opts.Runs),
		fmt.Sprintf("-max_total_time=%d", opts.MaxSeconds),
		"-use_value_profile=1",
		"-print_final_stats=1",
		"-artifact_prefix=" + artifactDir + string(os.PathSeparator),
		"-dict=" + dictAbs,
		corpusDir,
	}
	logPath := filepath.Join(runDir, "libfuzzer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return result, err
	}
	var tailBuf tailWriter
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = io.MultiWriter(logFile, &tailBuf)
	cmd.Stderr = io.MultiWriter(logFile, &tailBuf)
	cmdErr := cmd.Run()
	closeErr := logFile.Close()
	if closeErr != nil {
		return result, closeErr
	}
	result.LogPath = a.rel(logPath)
	result.LogTail = tailBuf.String()
	if cmdErr != nil {
		result.CommandExitError = cmdErr.Error()
	}

	files, err := collectCorpusFiles(corpusDir, artifactDir)
	if err != nil {
		return result, err
	}
	if len(files) == 0 {
		return result, fmt.Errorf("libFuzzer produced no corpus files")
	}
	bundle, records, err := packFuzzBundle(files)
	if err != nil {
		return result, err
	}
	snap, err := a.WS.SnapshotBytes("libfuzzer", "corpus-"+started.Format("20060102T150405"),
		result.RunDir, bundle, started)
	if err != nil {
		return result, err
	}
	if existing, err := a.DB.GetMaterial(snap.Material.ID); err == nil {
		if existing.SHA256 != snap.Material.SHA256 {
			return result, fmt.Errorf("fuzz bundle material id collision")
		}
	} else if err == store.ErrNotFound {
		if err := a.DB.AddMaterial(snap.Material); err != nil {
			return result, err
		}
	} else {
		return result, err
	}
	imported, importedRecords, err := a.importFuzzSamples(snap.Material, records, started)
	if err != nil {
		return result, err
	}
	result.MaterialID = snap.Material.ID
	result.BundlePath = snap.Material.SnapshotPath
	result.BundleSHA256 = snap.Material.SHA256
	result.CorpusFiles = len(importedRecords)
	result.ImportedSamples = imported
	result.Files = importedRecords
	finished := a.now()
	result.FinishedAt = model.Timestamp(finished)
	manifest := fuzzManifest{
		Schema: "serrfix.fuzz-manifest/v1", StartedAt: result.StartedAt,
		FinishedAt: result.FinishedAt,
		Command:    append([]string{binary}, args...), Target: targetAbs,
		Dictionary: dictAbs, SeedCount: seedCount, BundlePath: snap.Material.SnapshotPath,
		BundleSHA: snap.Material.SHA256, Files: importedRecords,
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return result, err
	}
	manifestData = append(manifestData, '\n')
	manifestPath := filepath.Join(runDir, "manifest.json")
	if err := a.atomicWrite(manifestPath, manifestData, 0o444); err != nil {
		return result, err
	}
	result.ManifestPath = a.rel(manifestPath)
	if err := a.DB.AddEvent(result.FinishedAt, "fuzz_completed", "", "",
		fmt.Sprintf(`{"material_id":%q,"files":%d,"imported":%d,"seed_count":%d,"log":%q}`,
			snap.Material.ID, len(files), imported, seedCount, result.LogPath)); err != nil {
		return result, err
	}
	return result, nil
}

func (a *App) writeSeeds(corpusDir string, maxSeeds int) (int, error) {
	samples, err := a.DB.ListSamples()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, sample := range samples {
		if count >= maxSeeds {
			break
		}
		material, err := a.DB.GetMaterial(sample.MaterialID)
		if err != nil {
			return count, err
		}
		data, err := a.readSample(sample, material)
		if err != nil {
			return count, err
		}
		name := fmt.Sprintf("seed-%03d-%s", sample.Ordinal, sample.SHA256[:12])
		if err := os.WriteFile(filepath.Join(corpusDir, name), data, 0o644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func collectCorpusFiles(dirs ...string) ([]string, error) {
	var files []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
				continue
			}
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func packFuzzBundle(paths []string) ([]byte, []FuzzFile, error) {
	var bundle bytes.Buffer
	bundle.WriteString(fuzzBundleMagic)
	records := make([]FuzzFile, 0, len(paths))
	seen := map[string]bool{}
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		base := filepath.Base(path)
		if seen[base] {
			base = fmt.Sprintf("%03d-%s", i, base)
		}
		seen[base] = true
		nameEncoded := base64.RawURLEncoding.EncodeToString([]byte(base))
		fmt.Fprintf(&bundle, "FILE %d %s\n", len(data), nameEncoded)
		offset := int64(bundle.Len())
		bundle.Write(data)
		bundle.WriteByte('\n')
		records = append(records, FuzzFile{
			Name: base, BundleOffset: offset, Length: int64(len(data)),
			SHA256: model.SHA256(data),
		})
	}
	return bundle.Bytes(), records, nil
}

func (a *App) importFuzzSamples(material store.Material, records []FuzzFile,
	createdAt time.Time) (int, []FuzzFile, error) {
	ordinal, err := a.DB.MaxSampleOrdinal()
	if err != nil {
		return 0, records, err
	}
	imported := 0
	for i := range records {
		record := &records[i]
		ordinal++
		label := "libfuzzer/" + record.Name
		if len(label) > 96 {
			label = label[:96]
		}
		id := fmt.Sprintf("s-%03d-%s", ordinal, record.SHA256[:12])
		params := model.DefaultParams(label)
		source := model.SourceRef{
			MaterialID: material.ID, Offset: record.BundleOffset,
			Length: record.Length, SHA256: record.SHA256,
		}
		c := model.Case{
			Schema: model.SchemaCase, SampleID: id, Label: label,
			Origin: "libfuzzer", Params: params, Source: source,
			CreatedAt: model.Timestamp(createdAt),
			Command: fmt.Sprintf("serrfix rerun --workspace %q --sample %s",
				a.WS.Root, id),
		}
		caseJSON, _ := json.Marshal(c)
		paramsJSON, _ := json.Marshal(params)
		sample := model.Sample{
			ID: id, Ordinal: ordinal, Label: label, Origin: "libfuzzer",
			MaterialID: material.ID, Offset: record.BundleOffset,
			Length: record.Length, SHA256: record.SHA256,
			ParamsJSON: string(paramsJSON), CaseJSON: string(caseJSON),
			CreatedAt: createdAt,
		}
		if _, err := a.DB.GetSample(id); err == nil {
			continue
		} else if err != store.ErrNotFound {
			return imported, records, err
		}
		if err := a.DB.AddSample(sample); err != nil {
			return imported, records, err
		}
		record.SampleID = id
		imported++
	}
	return imported, records, nil
}

func fileUpToDate(binary, source string) bool {
	bi, err := os.Stat(binary)
	if err != nil {
		return false
	}
	si, err := os.Stat(source)
	if err != nil {
		return false
	}
	return !bi.ModTime().Before(si.ModTime())
}

func tail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

type tailWriter struct {
	data []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	if len(w.data) > 4096 {
		w.data = append([]byte(nil), w.data[len(w.data)-4096:]...)
	}
	return len(p), nil
}

func (w *tailWriter) String() string { return strings.TrimSpace(string(w.data)) }

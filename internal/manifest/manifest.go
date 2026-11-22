package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"seedreview/internal/model"
)

type Parsed struct {
	Recovery model.Recovery
	Raw      []byte
	Path     string
}

func ParseFile(path string) (Parsed, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Parsed{}, fmt.Errorf("resolve manifest path: %w", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return Parsed{}, fmt.Errorf("read manifest: %w", err)
	}
	parsed, err := Parse(raw, filepath.Dir(abs))
	if err != nil {
		return Parsed{}, err
	}
	parsed.Path = abs
	return parsed, nil
}

func Parse(raw []byte, baseDir string) (Parsed, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return Parsed{}, fmt.Errorf("decode recovery manifest: %w", err)
	}

	sourceFormat := "legacy-v1"
	recoveryRoot := root
	if recovery, ok := objectValue(root["recovery"]); ok {
		sourceFormat = "canonical-v2"
		recoveryRoot = recovery
	} else if version := intValue(root["schema_version"]); version >= 2 {
		return Parsed{}, fmt.Errorf("schema_version %d requires a recovery object", version)
	}

	recovery := model.Recovery{
		SourceFormat:  sourceFormat,
		RecoveryID:    firstString(recoveryRoot, "id", "recovery_id", "session_id"),
		CapturedAt:    firstString(recoveryRoot, "captured_at", "timestamp", "time"),
		AppVersion:    firstString(recoveryRoot, "app_version", "version"),
		RNGAlgorithm:  rngAlgorithm(recoveryRoot),
		Seed:          seedValue(recoveryRoot, "seed", "initial_seed"),
		RecoveredSeed: seedValue(recoveryRoot, "recovered_seed", "seed_after_recovery"),
		StateSHA256:   firstString(recoveryRoot, "state_sha256", "seed_state_sha256", "state_hash"),
		Target:        firstString(recoveryRoot, "target", "target_path", "binary"),
		Artifact:      firstString(recoveryRoot, "artifact", "artifact_path", "input", "input_path"),
		Environment:   environmentValue(recoveryRoot),
		Notes:         firstString(recoveryRoot, "notes", "note", "comment"),
	}
	if sourceFormat == "canonical-v2" {
		fillCanonicalV2(&recovery, root, recoveryRoot)
	}
	if recovery.RecoveredSeed == "" {
		recovery.RecoveredSeed = recovery.Seed
	}
	if recovery.Target == "" {
		return Parsed{}, fmt.Errorf("%s manifest is missing target", sourceFormat)
	}
	if recovery.Artifact == "" {
		return Parsed{}, fmt.Errorf("%s manifest is missing artifact/input path", sourceFormat)
	}
	recovery.Target = resolvePath(baseDir, recovery.Target)
	recovery.Artifact = resolvePath(baseDir, recovery.Artifact)

	sum := sha256.Sum256(raw)
	recovery.Key = "manifest:" + hex.EncodeToString(sum[:])
	if recovery.RecoveryID == "" {
		recovery.RecoveryID = "legacy-" + hex.EncodeToString(sum[:6])
	}
	return Parsed{Recovery: recovery, Raw: raw}, nil
}

func fillCanonicalV2(recovery *model.Recovery, root, recoveryRoot map[string]any) {
	rng, _ := objectValue(recoveryRoot["rng"])
	if recovery.RNGAlgorithm == "" {
		recovery.RNGAlgorithm = stringValue(rng["algorithm"])
	}
	if recovery.Seed == "" {
		recovery.Seed = seedValue(rng, "seed")
	}
	if recovery.RecoveredSeed == "" {
		recovery.RecoveredSeed = seedValue(rng, "restored_seed", "recovered_seed")
	}
	if recovery.StateSHA256 == "" {
		recovery.StateSHA256 = firstString(rng, "state_sha256", "state_hash")
	}
	if recovery.Target == "" {
		replay, _ := objectValue(root["replay"])
		recovery.Target = firstString(replay, "target", "target_path")
	}
	if recovery.Artifact == "" {
		replay, _ := objectValue(root["replay"])
		recovery.Artifact = firstString(replay, "artifact", "artifact_path")
	}
	if len(recovery.Environment) == 0 {
		recovery.Environment = environmentValue(root)
	}
}

func rngAlgorithm(root map[string]any) string {
	if value := firstString(root, "rng_algorithm", "rng"); value != "" {
		return value
	}
	if rng, ok := objectValue(root["rng"]); ok {
		return firstString(rng, "algorithm", "name")
	}
	return ""
}

func seedValue(root map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := root[key]; ok {
			return stringValue(value)
		}
	}
	if rng, ok := objectValue(root["rng"]); ok {
		for _, key := range keys {
			if value, ok := rng[key]; ok {
				return stringValue(value)
			}
		}
	}
	return ""
}

func environmentValue(root map[string]any) map[string]string {
	value, ok := objectValue(firstValue(root, "environment", "env"))
	if !ok {
		return map[string]string{}
	}
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = stringValue(item)
	}
	return result
}

func firstString(root map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := root[key]; ok {
			text := stringValue(value)
			if text != "" {
				return text
			}
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func intValue(value any) int {
	text := stringValue(value)
	parsed, _ := strconv.Atoi(text)
	return parsed
}

func firstValue(root map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := root[key]; ok {
			return value
		}
	}
	return nil
}

func objectValue(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

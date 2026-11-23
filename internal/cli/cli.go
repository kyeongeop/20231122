package cli

import (
	"context"
	"fmt"

	"idorfix/internal/domain"
	"idorfix/internal/exchange"
	"idorfix/internal/store"
)

const defaultDB = "idorfix.db"

// Execute dispatches the CLI. The command surface is deliberately small and
// every destructive or long-running action works per-sample.
func Execute(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	command := args[0]
	rest := args[1:]

	switch command {
	case "init":
		return cmdInit(ctx, rest)
	case "import":
		return cmdImport(ctx, rest)
	case "list":
		return cmdList(ctx, rest)
	case "run":
		return cmdRun(ctx, rest)
	case "replay":
		return cmdReplay(ctx, rest)
	case "runs":
		return cmdRuns(ctx, rest)
	case "compare":
		return cmdCompare(ctx, rest)
	case "export":
		return cmdExport(ctx, rest)
	case "verify":
		return cmdVerify(ctx, rest)
	case "reload":
		return cmdReload(ctx, rest)
	case "recover":
		return cmdRecover(ctx, rest)
	case "version":
		fmt.Println(exchange.ToolVersion)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Print(`idorfix - multi-tenant IDOR local correction workbench

Usage:
  idorfix init [--db PATH]
  idorfix import --file SAMPLE.json [--db PATH]
  idorfix list [--db PATH]
  idorfix run --sample SAMPLE_ID [--db PATH]
  idorfix replay --sample SAMPLE_ID [--db PATH]
  idorfix runs --sample SAMPLE_ID [--db PATH]
  idorfix compare --sample SAMPLE_ID --a RUN_ID --b RUN_ID [--db PATH]
  idorfix export --sample SAMPLE_ID --run RUN_ID --out DIR [--db PATH]
  idorfix verify --bundle DIR
  idorfix reload --bundle DIR [--db PATH]
  idorfix recover [--db PATH]
  idorfix version

All artefacts use a fixed field order and SHA-256 checksums so that another
analyst can independently verify every exported record.
`)
}

func openStore(ctx context.Context, dbPath string) (*store.Store, error) {
	if dbPath == "" {
		dbPath = defaultDB
	}
	workspace, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	if err := workspace.SetMeta(ctx, "schema_version", fmt.Sprint(domain.SchemaVersion)); err != nil {
		workspace.Close()
		return nil, err
	}
	return workspace, nil
}

func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for index := 0; index < len(args); index++ {
		token := args[index]
		if len(token) > 2 && token[:2] == "--" {
			body := token[2:]
			if equals := indexOfByte(body, '='); equals >= 0 {
				flags[body[:equals]] = body[equals+1:]
				continue
			}
			key := body
			if index+1 < len(args) && (len(args[index+1]) < 2 || args[index+1][:2] != "--") {
				flags[key] = args[index+1]
				index++
				continue
			}
			flags[key] = "true"
		}
	}
	return flags
}

func indexOfByte(value string, target byte) int {
	for index := 0; index < len(value); index++ {
		if value[index] == target {
			return index
		}
	}
	return -1
}

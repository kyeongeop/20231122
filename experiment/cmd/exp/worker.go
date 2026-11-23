package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	snapv1 "yamlaliasexp/internal/snap/v1"
	snapv2 "yamlaliasexp/internal/snap/v2"
)

type metricsWire struct {
	ExpandedNodes int `json:"expanded_nodes"`
	AliasRefs     int `json:"alias_refs"`
	MaxDepth      int `json:"max_depth"`
}

type workerOut struct {
	OK      bool         `json:"ok"`
	Limit   bool         `json:"limit,omitempty"`
	Error   string       `json:"error,omitempty"`
	Metrics *metricsWire `json:"metrics,omitempty"`
}

// runWorker parses stdin with the chosen snapshot. It caps its own
// address space first so the vulnerable snapshot fails safely.
func runWorker(snap string, memMB int) error {
	limit := uint64(memMB) << 20
	if err := syscall.Setrlimit(syscall.RLIMIT_AS,
		&syscall.Rlimit{Cur: limit, Max: limit}); err != nil {
		return fmt.Errorf("setrlimit: %w", err)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	out := workerOut{}
	switch snap {
	case "v1":
		_, m, perr := snapv1.Parse(data)
		if perr != nil {
			out.Error = perr.Error()
		} else {
			out.OK = true
		}
		if m != nil {
			out.Metrics = &metricsWire{m.ExpandedNodes, m.AliasRefs, m.MaxDepth}
		}
	case "v2":
		_, m, perr := snapv2.Parse(data, snapv2.DefaultLimits())
		var le *snapv2.LimitError
		switch {
		case errors.As(perr, &le):
			out.Limit = true
			out.Error = perr.Error()
		case perr != nil:
			out.Error = perr.Error()
		default:
			out.OK = true
		}
		if m != nil {
			out.Metrics = &metricsWire{m.ExpandedNodes, m.AliasRefs, m.MaxDepth}
		}
	default:
		return fmt.Errorf("unknown snapshot %q", snap)
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

type parseOutcome struct {
	Result    string       `json:"result"`
	Error     string       `json:"error,omitempty"`
	Metrics   *metricsWire `json:"metrics,omitempty"`
	ElapsedMs int64        `json:"elapsed_ms"`
}

// runIsolated parses content in a fresh worker subprocess with a
// memory ceiling and timeout, classifying the outcome.
func (r *runner) runIsolated(snap string, content []byte, memMB int) parseOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.self, "-worker",
		"-snap", snap, "-mem-mb", strconv.Itoa(memMB))
	cmd.Stdin = bytes.NewReader(content)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start).Milliseconds()

	if ctx.Err() == context.DeadlineExceeded {
		return parseOutcome{Result: "timeout", Error: "killed after 6s", ElapsedMs: elapsed}
	}
	if err != nil {
		tail := stderr.String()
		if len(tail) > 400 {
			tail = tail[:400]
		}
		return parseOutcome{Result: "crash", Error: tail, ElapsedMs: elapsed}
	}
	var out workerOut
	if jerr := json.Unmarshal(stdout.Bytes(), &out); jerr != nil {
		return parseOutcome{Result: "crash", Error: "bad worker output: " + jerr.Error(), ElapsedMs: elapsed}
	}
	o := parseOutcome{Error: out.Error, Metrics: out.Metrics, ElapsedMs: elapsed}
	switch {
	case out.OK:
		o.Result = "ok"
	case out.Limit:
		o.Result = "limit_exceeded"
	default:
		o.Result = "parse_error"
	}
	return o
}

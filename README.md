# 20231122 — HTTP 请求走私处理过程重建

用 Go + libFuzzer + SQLite 重建 HTTP 请求走私（HTTP Request Smuggling）的
完整处理过程：攻击输入 → 前后端解析差异 → 连接复用 → 权限判断 → 日志证据。

## 结构

- `internal/httpwire` — 原始 HTTP/1.1 字节流解析器与 keep-alive 连接复用；
  四种解析 profile：`frontend`（CL 优先、取首个 CL、严格 TE）、
  `frontend-te`（TE 优先）、`backend`（TE 优先、取末个 CL、宽松 TE）、
  `backend-cl`（CL 优先、取末个 CL）。
- `internal/smuggle` — 去同步分析：前端解析客户端流并转发到复用连接，
  后端再解析；后端多服务的请求即走私请求，逐个做权限判断
  （`/admin` 需要 `X-Admin-Token`）；后端残留字节用 victim 请求检测连接投毒。
- `internal/scenario` — 极限参数场景集：CL.TE、TE.CL、重复 CL、混淆 TE、
  空输入、16 MiB 超大输入（1 MiB 入口上限）、边界前后样本
  （`MaxBodyBytes=4`：4 字节接受 / 6 字节拒绝）。
- `internal/evidence` — SHA-256 哈希、有界摘要、完整载荷落盘。
- `internal/store` — SQLite 证据库（`runs` / `parse_results` /
  `smuggled_requests` / `permissions` / `evidence` / `boundaries` / `logs`）。
- `cmd/smugglex` — 场景流水线 CLI，输出 攻击输入→触发位置→权限→日志 报告。
- `fuzz/harness` — 共享模糊测试 harness（原生 `go test -fuzz` 与 libFuzzer 共用）。
- `fuzz/libfuzzer` — libFuzzer 入口（`LLVMFuzzerTestOneInput`）。

## 运行

```sh
go build -o artifacts/smugglex ./cmd/smugglex
./artifacts/smugglex            # 证据写入 artifacts/evidence/audit.db
go test ./...                   # 单元测试
go test -run=^$ -fuzz=FuzzSmuggle -fuzztime=30s ./fuzz/harness/
```

## libFuzzer 构建与运行

```sh
CGO_ENABLED=1 CC=clang \
go build -buildmode=c-archive -tags=libfuzzer -gcflags=all=-d=libfuzzer \
  -o /tmp/smuggle-fuzz.a ./fuzz/libfuzzer
clang -fsanitize=fuzzer -o artifacts/fuzz/smuggle-fuzz /tmp/smuggle-fuzz.a
./artifacts/fuzz/smuggle-fuzz artifacts/fuzz/corpus -max_total_time=60 -max_len=4096
```

## 证据

- SQLite：`artifacts/evidence/audit.db`（每个场景一次 run，七张表关联 `run_id`）。
- 走私请求与超大输入原文：`artifacts/evidence/files/*.bin`（按 SHA-256 命名）。
- 种子语料：`artifacts/fuzz/corpus/CASE-*.http`、`BOUNDARY-*.http` 及
  libFuzzer 合并产生的新样本。

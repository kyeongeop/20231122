# 系统调用白名单来源检查

对“系统调用白名单”来源做审计：记录两个版本快照与一条被截断的记录，
让每个结论都能回溯到原始输入和处理步骤；对无法判断的边界保留关键证据；
单条记录异常后继续处理其余对象；结束时清理临时状态。

技术栈固定为 **Go + libFuzzer + SQLite**。

## 目录结构

- `cmd/whitelist-audit/`：审计主程序，装载快照、逐条检查、产出 SQLite 与 HTML 检查页。
- `internal/model/`：领域模型（来源、快照、记录、结论、证据步骤）。
- `internal/store/`：SQLite 持久层（纯 Go 驱动 `modernc.org/sqlite`，避免与 cgo/libFuzzer 冲突）。
- `internal/checker/`：检查流水线与证据链，含 panic recover 隔离。
- `internal/tempstate/`：每条记录独立临时目录的分配与统一清理。
- `internal/report/`：HTML 检查页生成。
- `fuzz/libfuzzer/`：通过 cgo 暴露 `LLVMFuzzerTestOneInput` 的 libFuzzer 目标。
- `fuzz/build.sh`、`fuzz/run.sh`：构建与运行 fuzz 目标。
- `testdata/registry.json`：受信任来源 + 两个白名单版本快照（v1、v2）。
- `testdata/records.json`：8 条待检查记录（含 1 条截断记录、1 条解析异常）。

## 检查流水线与证据链

每条记录按固定阶段处理，每个阶段写入一条 `EvidenceStep`（阶段、说明、
输入证据、产出），并把原始输入的 SHA-256 与长度存入 SQLite：

1. `ingest`：接收原始信封并计算字节哈希。
2. `tempstate`：在隔离临时目录落地处理状态。
3. `parse`：解析失败标记为 `error` 并隔离，不影响后续记录。
4. `truncation`：截断记录判为 `undecidable`，保留截断长度、原始哈希、声明版本。
5. `source_lookup`：来源不在登记表则 `rejected`。
6. `signature`：签名公钥指纹不一致则 `rejected`。
7. `snapshot_lookup`：声明版本无快照判为 `undecidable`（边界，非明确拒绝）。
8. `syscall_match`：调用号不在快照白名单则 `rejected`，否则 `trusted`。

四类结论：`trusted`（可信）、`rejected`（拒绝）、`undecidable`（无法判断）、
`error`（处理异常，已隔离并继续）。

无法判断的边界有两处，均保留关键证据：

- `rec-003`：传输中被截断，签名/负载不完整。
- `rec-005`：声明的白名单版本 `v9` 没有对应快照。

## 运行审计

```bash
go run ./cmd/whitelist-audit
```

默认输入 `testdata/*.json`，产物：

- `artifacts/audit.db`：SQLite，表 `trusted_sources`、`snapshots`、`findings`、`raw_inputs`。
- `artifacts/check-page.html`：检查页，含每条结论的原始输入、哈希、逐步证据与清理状态。

参考结果：8 条记录 = 2 trusted / 3 rejected / 2 undecidable / 1 error，
临时根目录删除、残留工作目录 0 个。

## 运行测试

```bash
go test ./...
```

## libFuzzer

Go 侧通过 `//export` 把检查流水线暴露给 C，再用 clang 的
`-fsanitize=fuzzer,address` 链接为可执行文件。fuzz 输入使用纯内存 SQLite，
每轮结束校验临时目录无泄漏。

```bash
# 需要 clang（含 libclang_rt.fuzzer），脚本内固定 GOTOOLCHAIN=local
./fuzz/build.sh
./fuzz/run.sh            # 默认 20000 轮；RUNS=100000 ./fuzz/run.sh
```

说明：当前 Go 编译器不产生 libFuzzer 原生覆盖率插桩，fuzz 主要用于
稳定性与“无崩溃、无临时状态泄漏”验证；崩溃捕获链路已用独立 C 目标对照验证。

## 工具链

本仓库在无 root 环境下使用本地工具链（Go 1.24.4、clang/LLVM 21，含
`libclang_rt.fuzzer-x86_64.a`）。依赖固定为兼容 Go 1.24 的
`modernc.org/sqlite v1.34.5`，并设置 `GOTOOLCHAIN=local` 避免自动下载新工具链。

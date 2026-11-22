# 静态文件缓存泄露 · 可回放实验

这个实验复现一个受控的静态文件缓存缺陷：缓存键只由 `METHOD + path` 组成，
没有包含快照/版本。两个版本快照拥有完全相同的静态路径和未知扩展名
`.q7x`，因此第二个版本请求会命中第一个版本留下的缓存对象。

固定技术栈：

- Go：实验编排、场景执行、SQLite 读写、证据封存和独立审计。
- libFuzzer：把同一条缓存键规则编译为 C++ 断言目标，命中后生成 crash artifact。
- SQLite：对象、快照、每个步骤的输入/状态/结果、验证结论和清理凭据的唯一事实源。

## 复现结论

控制快照：

| 快照 | 版本标签 | 路径 | 未知扩展 | 内容 SHA-256 |
|---|---|---|---|---|
| `snap-v1` | `release-2026.11.22-a` | `/static/opaque.q7x` | `.q7x` | `a1c4166475205b20...3263357` |
| `snap-v2` | `release-2026.11.22-b` | `/static/opaque.q7x` | `.q7x` | `0a08b16db15f3307...20de0c41` |

预期行为与实测一致：

1. `v1 -> v2`：v1 为 `MISS`；随后 v2 为 `HIT`，但返回 v1 字节并标记泄露。
2. `v2 -> v1`：v2 为 `MISS`；随后 v1 为 `HIT`，但返回 v2 字节并标记泄露。
3. 对同一对象的后续重复提交继续返回同一份陈旧字节，哈希不变。
4. `partial.q7x` 在 v2 中故意缺失，产生一次隔离的 404；其后 `tail.q7x`
   仍继续处理，并再次复现 v1 字符串泄露。

## 快速运行

依赖：Go 1.24+、Clang/libFuzzer。SQLite 使用纯 Go 驱动，不需要 CGO。

```bash
make test
make run FUZZ=run
make verify
```

直接命令：

```bash
go run . run --workspace evidence --run-id uid6-0044-replay \
  --fuzz run --fuzz-runs 2000
go run . report --workspace evidence --run-id uid6-0044-replay
go run . verify --workspace evidence --run-id uid6-0044-replay
```

也可以设置 `CACHELEAK_CLANGXX` 或 `--clangxx` 指向特定 `clang++`。若只是做
SQLite 场景测试，可使用 `--fuzz skip`；此时审计会明确报告 libFuzzer 未完成，
不会把它伪装成通过。

本次归档运行 `uid6-0044-replay` 的结果：

- 5 个场景、20 个请求步骤、37 个只读证据对象，运行状态 `completed`。
- libFuzzer 运行 2000 次，退出码 77，命中版本盲缓存键断言并保留 crash artifact。
- artifact SHA-256：`c4d9fd3b0c81f0d3ee35ba96e30751ed1b9e9c7f331596a31c5bd26e19803325`。
- 独立审计 15 项全部通过，`evidence/.tmp` 不存在。

## 五个场景

| 场景 | 顺序/动作 | 验证点 |
|---|---|---|
| `order-forward` | v1, v2, v2, v2 | 改变顺序后 v2 命中 v1 缓存；重复提交稳定 |
| `order-reverse` | v2, v1, v1, v1 | 反向顺序命中 v2 缓存，证明不是固定内容错误 |
| `repeat-forward-a` | v1, v2, v2 | 同进程重复提交 |
| `repeat-forward-b` | v1, v2, v2 | 新缓存重放同一脚本，跨回放结果一致 |
| `error-continuation` | v1, v2, 404, tail-v1, tail-v2, tail-v2 | 404 后继续处理剩余对象 |

所有 20 个请求都写入 `steps` 表。每行包含：

- `input_json`：方法、路径、快照 ID、请求头和提交序号。
- `state_before_json` / `state_after_json`：有序缓存键、条目元数据、选中快照和临时根目录状态。
- `result_json`：状态码、`HIT/MISS/ERROR`、实际服务快照、期望/实际 SHA-256、字节数和泄露标记。
- `evidence_id`：对应的只读步骤 JSON 原件。

## SQLite 与证据

主要表：

| 表 | 用途 |
|---|---|
| `runs` | 运行状态、配置、时间与最终摘要 |
| `snapshots` | v1/v2 控制快照 |
| `objects` | 原始字节 BLOB、路径、未知扩展、MIME、大小和 SHA-256 |
| `scenarios` | 顺序、计数、临时路径与清理状态 |
| `steps` | 每步输入、执行前状态、执行后状态和结果 |
| `evidence` | 只读证据文件路径、大小、SHA-256 和分类 |
| `verifications` | 顺序、重复、异常续跑、fuzz、清理的机器可读结论 |
| `repeat_groups` | 重复提交的哈希/缓存状态聚合 |
| `cleanup` | 临时路径删除前后状态 |
| `fuzz_runs` | libFuzzer 命令、退出码、日志与 crash artifact |

最终运行会封存：

- `evidence/evidence.db`：完整 SQLite 事实源。
- `evidence/evidence/<run-id>/manifest.json`：全部证据对象及哈希清单。
- `evidence/evidence/<run-id>/step-*.json`：每步原始输入、状态和结果。
- `evidence/evidence/<run-id>/snap-v*-*.bin`：两个快照的原始字节。
- `evidence/evidence/<run-id>/libfuzzer.log`：libFuzzer 完整输出。
- `evidence/evidence/<run-id>/crash-*`：版本盲缓存键的崩溃输入。
- `evidence/summary.json` 与 `evidence/audit.json`：便于人工查看的最终摘要和独立审计。

## libFuzzer

`fuzz/cache_key_fuzzer.cpp` 使用与 Go 实验相同的两快照、同路径、同未知扩展模型。
第二次请求若仍服务第一个快照，目标输出：

```text
CACHELEAK_ASSERT: ... version-omitted-from-cache-key
```

并执行 `__builtin_trap()`。Go 编排器用
`-fsanitize=fuzzer,address` 编译目标，运行后同时封存 stdout/stderr 和
`-artifact_prefix` 下的 crash 文件。libFuzzer 的非零退出是预期发现，不算编排失败；
审计会重新计算 artifact 和日志的 SHA-256。

独立运行：

```bash
cd fuzz
./build.sh
FUZZ_RUNS=2000 ./run.sh
```

## 异常与清理

- 每个请求通过 `recover` 包装；未知快照、缺失对象、方法错误或意外 panic 只影响当前步骤。
- 场景循环在单步异常后继续，后续场景也不受前一个场景失败影响。
- 所有场景和 fuzz 产物先封存到 SQLite/evidence，再删除 `evidence/.tmp/<run-id>`。
- `cleanup` 表和 cleanup 验证同时记录删除前存在、删除后不存在。
- 即使运行中期返回错误，也有 best-effort defer 删除临时根目录。

## 独立审计

`go run . verify` 不依赖运行时的“通过”标记，而是重新读取 SQLite 并检查：

- 两个快照和一个未注册 `.q7x` 扩展。
- 每个对象 BLOB 的 SHA-256 与大小。
- 每个 evidence 文件的存在性、只读权限和 SHA-256。
- 每步输入、执行前后状态、结果和 UTC 时间顺序。
- 正向/反向顺序泄露、重复提交确定性、404 后继续处理。
- 所有记录的执行结论、清理凭据和临时路径不存在。
- libFuzzer artifact 与日志的文件哈希。

通过时输出 `"ok": true` 并以 0 退出；任一检查失败则非零退出。

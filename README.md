# TLS 配置回归 — 可回放实验

对两个冻结的 TLS 配置解析器快照（v1 基线 / v2 重构版）做差分回归实验。
每一步的输入、状态与结果都写入 SQLite 日志，可随时回放验证。

## 技术栈

- **Go**：实验运行器与两个解析器快照（`internal/tlscfg`、`cmd/tlsreg`）
- **libFuzzer 式覆盖率模糊测试**：Go 工具链内置的 libFuzzer 风格引擎
  （`go test -fuzz`，见 `internal/tlscfg/fuzz_test.go`），对两个快照做差分模糊
- **SQLite**（`modernc.org/sqlite`，纯 Go）：实验日志库 `artifacts/experiment.db`

## 实验设计

- 语料 10 条记录（`cmd/tlsreg/corpus.go`），其中 `rec-ctl-truncated`
  是被截断的 JSON，作为对照：两个快照都必须报错，且运行器必须继续处理后续记录。
- 阶段 A `baseline`：逐条记录跑 v1/v2，记录结果并比对分歧。
- 阶段 B `order`：seed+1 打乱顺序重跑，验证结果与顺序无关。
- 阶段 C `duplicate`：每条记录重复提交两次，验证幂等。
- 阶段 D `fuzz`：差分模糊 60s（约 189 万次执行），忽略三处已知行为差异
  （ALPN 默认值移除、TLS1.2 下限、默认密码套件变更），只报告无法解释的分歧。
- 清理：运行器在结束时删除自身临时目录并验证；模糊缓存等临时状态已清理。

## 复现 / 回放

```sh
./.tools/goenv go run ./cmd/tlsreg run    --db artifacts/experiment.db --artifacts artifacts
./.tools/goenv go run ./cmd/tlsreg replay --db artifacts/experiment.db --run <run_id>
./.tools/goenv go test ./internal/tlscfg/ -fuzz FuzzDifferential -fuzztime 60s
./.tools/goenv go run ./cmd/tlsreg report --db artifacts/experiment.db --run <run_id> --out artifacts/report.md
```

## 关键证据（artifacts/）

- `experiment.db` — SQLite 日志：`runs` / `steps`（每步输入 sha256、状态、结果、耗时）/ `comparisons`
- `report.md` — 本次运行报告（4 处分歧：rec-002、rec-003、rec-009、rec-010）
- `corpus.json` — 输入语料快照
- `fuzz/` — 模糊测试有趣输入样本（已回灌日志，phase=`fuzz`）
- `run.log` — 运行与回放日志

## 结果摘要

- 基线 10 条记录 × 2 快照：9 个错误（含截断对照），全部记录照常处理完毕。
- 乱序重放：0 处顺序依赖违规。重复提交：0 处不一致。
- 回放 104 步：0 处不匹配，日志可忠实回放。
- 模糊测试：60s 无未解释分歧；期间发现并归类了第三处已知差异（默认密码套件）。

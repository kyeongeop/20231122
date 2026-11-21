# 协议超时状态机 · 可回放实验

固定技术栈：**Go + libFuzzer（Go 原生覆盖率引导 fuzz 引擎，libFuzzer/AFL 同构）+ SQLite（纯 Go 驱动 `modernc.org/sqlite`，免 CGO）**。

## 1. 目标与设计

对一个确定性的“协议超时状态机”做可回放实验：

- 记录每一步的**输入、结果、后继状态与状态哈希**，逐条事务写入 SQLite。
- 在“恢复（RECOVER）”之后执行**恰好一次重放**，逐帧比对重放哈希与日志哈希。
- 注入一个**未知扩展 `X_PING` 作为对照**，要求被拒绝且不改变协议状态。
- 专门验证**顺序改变（乱序）**与**重复提交**两类输入。
- 报告将**自动结论**与**人工确认清单**分开呈现，并在失败时给出可执行后续操作。

状态集合：`INIT → CONNECTED → REQUEST_SENT → (TIMED_OUT → RECOVERING) → ACKED → CLOSED`。

## 2. 目录结构

| 路径 | 职责 |
|---|---|
| `internal/fsm` | 状态机核心、确定性状态哈希、单测与 fuzz 目标 |
| `internal/store` | SQLite 表结构、事务追加、有序回放读取、重放核对 |
| `internal/replay` | 场景定义（基线/未知扩展/乱序/重复）与执行+单次重放引擎 |
| `internal/report` | 自动判定与 Markdown/JSON 报告（自动结论 vs 人工确认分离） |
| `cmd/experiment` | 实验主入口，产出全部证据 |
| `cmd/dbquery` | 不依赖 sqlite3 CLI 的证据库检查工具 |
| `testdata/fuzz/FuzzMachine` | fuzz 固化语料（78 个种子） |
| `artifacts/experiment.db` | SQLite 证据库 |
| `evidence/` | `report.md`、`report.json`、各场景 `trace_*.json` |

## 3. 快速运行

```bash
./run.sh            # 单测 + 实验 + SQLite 证据核对
make test           # 仅单元/集成测试
make experiment     # 重新生成 artifacts 与 evidence
make query          # 打印表计数与有序事件日志
make fuzz           # 覆盖率引导 fuzz（默认 30s）
```

环境注意：本机 Go 在 `/tmp/go/bin`，模块缓存位于 `/home/hj/.gopath`。沙箱代理
`127.0.0.1:7897` 可能不可用，`run.sh` 已改用 `GOPROXY=https://goproxy.cn,direct`
并设置 `GOSUMDB=off`。

## 4. 关于 libFuzzer

本环境无 clang，无法编译 C/C++ 版 libFuzzer；Go 1.18+ 的原生 fuzz 引擎采用与
libFuzzer 相同的覆盖率引导、语料最小化与崩溃复现范式，入口 `FuzzMachine`
（见 `internal/fsm/fuzz_test.go`）即为 libFuzzer 兼容目标：

- 断言不 panic、重放哈希确定、未知扩展不会产生未定义状态、计数不变量成立。
- 实测约 1700 万次执行、81 个有趣输入、0 崩溃；固化 78 个种子到 `testdata`。

## 5. 证据与结论

- 自动结论见 `evidence/report.md` 第一节；全部场景 PASS，重放 mismatch=0。
- 逐步证据（输入/状态/结果/哈希）见同文件第三节与 `evidence/trace_*.json`。
- SQLite 三张表：`runs`、`events`、`replay_checks`，可用 `make query` 核对。

## 6. 失败时的可执行后续操作

1. 重放分歧：`make query` 查看 `replay_checks` 中 `match=0` 的行，比较
   `events.hash_after` 与 `replay_checks.replay_hash`，定位非确定转移后重跑
   `make experiment`。
2. fuzz 崩溃：失败样例会写入 `testdata/fuzz/FuzzMachine/`，直接
   `go test ./internal/fsm/ -run=FuzzMachine` 即可回归复现。
3. 状态机断言失败：`go test ./internal/fsm -run <TestName> -v` 单独复现。
4. 报告自动判定 FAIL：按 `evidence/report.md` 第一节对应场景给出的
   `failure_hint` 操作，修复后重新执行 `./run.sh`。

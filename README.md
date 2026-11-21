# WebSocket 授权绕过测试 · 来源检查页

技术栈：Go（判定管线 + 报告服务）、libFuzzer（模糊测试）、SQLite（来源存储）。

## 功能

- 运行记录含生命周期事件，包括**两次真实的中途取消**（SIGINT 中断的 libFuzzer 轮次）。
- 每条结论可回溯：原始输入（SHA-256）→ 处理步骤（parse/normalize/classify/conclude）→ 结论。
- 无法判断的边界案例（连接中断、非预期状态码）保留关键证据（部分抓包、日志）。
- 报告页将**自动结论**与**人工确认**分开呈现。
- 失败的运行附带**可执行的后续操作**。

## 构建与运行

```sh
# 1. 构建 libFuzzer 模糊测试器（需要 clang；可用 GO=/path/go CLANG=/path/clang 覆盖）
scripts/build_fuzz.sh

# 2. 运行模糊测试（Ctrl-C 即产生一次“中途取消”事件素材）
./fuzz/wsfuzz -max_total_time=60 corpus

# 3. 生成演示数据（读取 artifacts/fuzz_run*.log 作为证据）
go run ./cmd/seed

# 4. 启动来源检查页
go run ./cmd/server -addr 127.0.0.1:8080
```

## 结构

- `internal/checker` — 握手场景判定管线，输出结论 + 步骤链 + 证据
- `internal/store` — SQLite 持久化（runs/events/inputs/steps/conclusions/evidence/next_actions）
- `cmd/server` — 来源检查页（五个区块：运行记录 / 自动结论 / 人工确认 / 边界证据 / 失败后续）
- `cmd/seed` — 演示数据生成（真实执行 checker 管线后入库）
- `fuzz` — libFuzzer 桥接：Go 编译为 c-shared，clang `-fsanitize=fuzzer,address` 链接

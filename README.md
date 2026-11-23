# OAuth 回调校验可复核流程

技术栈固定为 **Go + libFuzzer + SQLite**（SQLite 通过纯 Go 的
`modernc.org/sqlite` 驱动访问，无 cgo 依赖冲突）。

## 目录

- `internal/callback/`：新旧格式解析、校验流水线、事件链与结论
- `internal/evidence/`：SQLite 证据库（cases/events/decisions/reviews 四表）
- `internal/runner/`：语料封装、固定策略、回放入库
- `internal/report/`：双分区 Markdown 报告生成
- `cmd/oauthreview/`：CLI（`replay` / `review` / `report`）
- `fuzz/seed/`：14 条精选用例（正常 2、取消 2、攻击/畸形 10）
- `fuzz/main.go` + `fuzz/fuzzentry.c`：libFuzzer 桥接 harness
- `scripts/fuzz.sh`：构建并运行 libFuzzer
- `scripts/run-all.sh`：一键完整流水线
- `docs/ARCHITECTURE.md`：设计与证据模型说明

## 快速开始

工具链约定（无 root 时本地安装）：

```bash
export PATH="$HOME/local/go/bin:$PATH"
export CLANG_BIN="$HOME/local/clang-root/usr/bin/clang"
export CLANG_LIB="$HOME/local/clang-root/usr/lib/llvm-21/lib"
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
```

一键运行（单元测试 → 回放 → 模糊测试 → 报告）：

```bash
scripts/run-all.sh
```

分步运行：

```bash
go test ./...                                   # 单元测试
go build -o bin/oauthreview ./cmd/oauthreview
bin/oauthreview replay --corpus fuzz/seed       # 回放并写入 reports/evidence.db
scripts/fuzz.sh 300000                          # libFuzzer，30 万次
bin/oauthreview report                          # 生成 reports/review-report.md

# 人工确认（自动结论与人工确认分表、分区呈现）
bin/oauthreview review --case C03-cancel-midflow \
  --reviewer zhang.san --confirm --notes "取消标记一致"
bin/oauthreview review --case C04-cancel-orphan \
  --reviewer zhang.san --reject --notes "缺服务端标记，转安全团队"
```

## 复核要点

- 自动结论（`ALLOW` / `DENY` / `CANCELLED`）与人工确认在报告中分成两个分区。
- 每条用例都有「攻击输入 → 触发位置 → 权限判断规则 → 日志证据哈希」对照表，
  原始输入保留在 SQLite `cases.raw_input`，重复入库会被拒绝。
- 失败用例在报告第三节给出按结论类型区分的可执行后续操作。
- 中途取消用例 `C03`（有服务端标记）与 `C04`（无标记、需人工核查）覆盖完整取消路径。

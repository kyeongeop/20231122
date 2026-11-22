# ckaudit — Cookie 属性审计局部修正工具

针对“缺失片段”（缺少 `Secure` / `HttpOnly` / `SameSite` 等）构造一组极限参数攻击样本，
让每个样本都能**单独重跑、相互比较、导出**，并支持**中途退出后重新进入**、保留**关键证据**。
每个极限参数在边界前后各取一个样本并记录审计结论的变化。

技术栈固定为 **Go + libFuzzer + SQLite**：

- Go：CLI 编排、样本生成、状态机、证据管理与导出（cgo 直链系统 `libsqlite3`，无外部 Go 模块）。
- libFuzzer（clang 18，ASan+UBSan）：C 审计目标 `fuzz/cookie_audit_fuzz.c`，同时产出独立重跑二进制。
- SQLite：`runs / samples / findings / evidence` 四张表，WAL 模式，断点状态持久化。

## 目录结构

```
cmd/ckaudit/              CLI 入口与子命令
internal/audit/           攻击样本 + 极限边界样本生成器
internal/runner/          工具链构建、单样本执行、libFuzzer 活动、锁与续跑
internal/store/           SQLite schema 与状态机
internal/sqlite/          零依赖 cgo SQLite 封装
fuzz/cookie_audit_fuzz.c  libFuzzer 目标（含独立 main 重跑模式）
scripts/env.sh            免 root 工具链激活（Go + clang-18）
```

## 一次性环境准备（免 root）

容器内默认没有 Go/clang，且 apt 代理失效。工具链已下载到 `~/.local/toolchain`：

```bash
source scripts/env.sh
make all          # 构建 ckaudit、libFuzzer 目标、独立重跑二进制
make test
```

`scripts/env.sh` 会设置 `GOROOT`、`PATH`、`LD_LIBRARY_PATH`、`CK_CLANG`，
并为只有 `libsqlite3.so.0` 的系统补齐开发符号链接。

## 工作流

```bash
W=./ckaudit-work

# 1) 生成 run 与全部样本（不执行任何样本）
./build/ckaudit init --work "$W" --name demo

# 2) 逐样本确定性重跑（可随时 Ctrl-C / SIGTERM）
./build/ckaudit run --work "$W"

# 3) 中断后重新进入：running 样本自动回退 pending，从未完成处继续
./build/ckaudit resume --work "$W"

# 4) 单个样本独立重跑（确定性，带审计明细）
./build/ckaudit rerun --work "$W" --sample attack/missing_secure

# 5) 边界前后变化、样本对比、导出
./build/ckaudit boundary --work "$W"
./build/ckaudit compare --work "$W" \
    --a boundary/maxage_zero/below --b boundary/maxage_zero/above
./build/ckaudit export --work "$W" --out report.json --format json \
    --evidence ./evidence-pack
./build/ckaudit export --work "$W" --out report.csv  --format csv

# 6) libFuzzer 持续模糊（种子=已生成样本，崩溃归档到 libfuzzer/crash）
./build/ckaudit fuzz --work "$W" --runs 50000 --jobs 2 --max-len 4096
```

## 样本模型

- **缺失片段攻击样本**（`scenario=missing-fragment-attack`）：缺 `Secure`/`HttpOnly`/`SameSite`、
  非法 `SameSite=None`、`__Host-`/`__Secure-` 前缀违规、空 Domain/Path、坏 Max-Age、
  控制字节、超长 Cookie、重复属性、大小写混淆等。
- **极限边界样本**（`scenario=extreme-boundary`）：每个参数在边界两侧各一个，字段
  `boundary / side(below|above) / param_value`：
  - `Max-Age=0`（-1 vs 1）、`Max-Age=INT32_MAX`（2147483646 vs 2147483648）
  - Max-Age 位数上限 24（23 位 vs 25 位，后者触发 `MAXAGE_BAD`）
  - 属性数上限 32（31 vs 33）、名字节数 256（255 vs 257）
  - 值字节数 4096（4095 vs 4097）、分号深度 32（31 vs 33）

审计结论分三级 `CRIT / WARN / INFO`，以 `CKA|...` 行从 C 目标输出，Go 侧解析入库。

## 断点、锁与证据

- **状态机**：`runs.status = running | interrupted | done | failed`；
  `samples.status = pending | running | ok | crash | error | skipped`，含 `attempts` 计数。
- **中断恢复**：每 2 秒心跳更新 `updated_at`；收到 SIGTERM/SIGINT 时完成当前样本后停止，
  `resume` 把残留 `running` 样本重新入队并继续。
- **并发锁**：`campaign.lock` 记录持有者 pid，基于 `/proc/<pid>` 判活；
  存活则拒绝新活动，`stop` 仅清理过期锁。
- **关键证据**：每个样本在 `evidence/<sample_id>/` 保留 `input.bin`、`stderr.log`，
  崩溃额外保存 `crash.log`；元数据（路径、sha256、字节数、时间）写入 `evidence` 表。
- **libFuzzer 证据**：`libfuzzer/libfuzzer.log`（含 final stats）与 `libfuzzer/crash/` 崩溃件。

## 退出码语义（单样本）

- `0` → `ok`；`>=70`（ASan/UBSan/libFuzzer 崩溃段）→ `crash`；其余 → `error`。

## 常用命令速查

```bash
./build/ckaudit list       # 所有 run 及样本计数
./build/ckaudit show --sample attack/missing_secure   # 单样本结论 + 证据
./build/ckaudit build      # 仅（重）编译两个 C 二进制
./build/ckaudit stop       # 清理过期锁（持锁进程存活时拒绝）
```

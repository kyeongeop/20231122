# DNS 名称编码校验 · 处理过程重建

技术栈固定：**Go**（DNS 名称编码校验判定管线）、**libFuzzer**（任意字节模糊测试，clang `-fsanitize=fuzzer,address`，经 Go c-shared 桥接）、**SQLite**（原始输入 / 锚点偏移 / 判定 / 证据持久化）。

## 输入模型与三段锚点

每个用例是一段原始字节，由三个锚点标记切成三段，对应题面的三类输入：

| 锚点 | 含义 | 校验内容 |
|---|---|---|
| `ANCHOR1` | DNS 名称（点分文本） | RFC 1035 长度（名称 253 / 标签 63）、LDH 字符集、空标签、连字符边界、非 ASCII 线上名称 |
| `ANCHOR2` | 编码标签（逗号分隔） | 标签数量一致、非 ASCII 名称必须有 `xn--` punycode 对应项、编码标签仍满足 LDH |
| `ANCHOR3` | 比较规则 | 仅接受 `exact` / `case-insensitive` / `idna`，并按规则重算后与编码标签逐标签比较 |

解析时记录每个锚点标记的**原始字节偏移**（marker offset）以及段内违规字节的**绝对原始偏移**（byte offset），验收直接落到这些偏移上。

## 异常场景与四要素对应

每条结论都把「攻击输入 → 触发位置 → 权限判断 → 日志证据」对齐：

- `case01` 下划线主机名：`ANCHOR1` 标记偏移 0、字节偏移 8，`ILLEGAL_CHARACTER` → **deny**
- `case02` 编码标签数量不一致：`ANCHOR2` 标记偏移 21、字节偏移 29，`LABEL_COUNT_MISMATCH` → **deny**
- `case03` 未知比较规则 `fuzzy-match`：`ANCHOR3` 标记偏移 42、字节偏移 50，`UNKNOWN_RULE` → **deny**
- 另有高位字节（必须先 punycode）、空标签、连字符边界等 `ANCHOR1` 场景，以及一个全锚点通过的 **allow** 用例

## 空输入与超大输入

- 空输入（`case08`，0 字节）：进入 `guard` 阶段即判 **undetermined**，保留 `raw_len=0` 与空串 SHA-256
- 超大输入（`case09`，65537 字节，上限 64 KiB）：判 **undetermined**，保留 256 字节前缀、完整长度与全量 SHA-256，不进入解析
- 两类边界都在 SQLite `next_actions` 中挂「人工研判」后续动作

## 原始材料保护

- `evidence/raw/*.raw` 为只读（`chmod 444`）的未修改原始材料，附 `SHA256SUMS` 清单
- SQLite `inputs` 表保存原始字节与 hex 转储，`store.VerifyIntegrity()` 每次出报告前重算 SHA-256 校验，任一不符即失败退出

## 构建与运行

```sh
source scripts/env.sh          # 本地 Go 1.23.4 + clang-18/libFuzzer 工具链

go test ./...                  # 单元测试（锚点偏移 / 三类攻击 / 空与超大输入）
scripts/build_fuzz.sh          # Go c-shared + clang libFuzzer/ASan 构建
mkdir -p corpus-work
./fuzz/dnsfuzz -max_total_time=30 corpus corpus-work   # 手工种子 + 工作语料分离

go run ./cmd/seed              # 对 evidence/raw 真实跑管线并写入 SQLite
go run ./cmd/report            # 生成 artifacts/report.json 与 report.md
go run ./cmd/inspect           # 免 sqlite3 CLI 的库内容审计

scripts/reproduce.sh           # 一键完整复现
```

## 目录

- `internal/checker` — 锚点切分、DNS 编码校验、比较规则、权限判定（deny/allow/undetermined）
- `internal/store` — SQLite schema 与存取 API（runs/events/inputs/anchors/steps/findings/conclusions/evidence/next_actions）
- `fuzz` — libFuzzer 桥接：Go 编为 c-shared，clang 链接 fuzzer+ASan
- `cmd/seed`、`cmd/report`、`cmd/inspect` — 入库、验收报告、库审计
- `evidence/raw` — 只读原始材料与 SHA-256 清单
- `corpus` — libFuzzer 种子语料
- `artifacts` — 数据库、模糊测试日志、验收报告

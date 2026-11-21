# krfix — 密钥轮换失效（Key-Rotation Failure）局部修正工具

针对“密钥轮换失效”缺陷的本地化复现、修正与取证工具。每个攻击样本都可以
**单独重跑、单独对比、单独导出**；支持**中途退出与重新进入**并保留全部关键
证据；原始材料**只写一次、只读封存、哈希钉死**，永不被修改。

技术栈固定为 **Go + libFuzzer + SQLite**：

- Go：控制平面（材料管理、任务编排、断点续跑、证据导出）
- libFuzzer/clang：漏洞版与局部修正版两套 harness（同一份 C 源码编译）
- SQLite：全部验收事实（时间点、原始偏移、判定、证据哈希、任务状态机）

## 1. 三段锚点模型

每份密封材料（108 字节定长帧）包含三段带 8 字节魔数的锚点：

| 锚点 | 魔数 | 含义 | 原始偏移 | 长度 |
|----|------|------|--------|----|
| #1 | `KRFIXH01` | header：当前 key_id 与服务端轮换 epoch | 0 | 16 |
| #2 | `KRFIXP02` | payload：密文 + 密封该帧的客户端 epoch | 16 | 48 |
| #3 | `KRFIXA03` | attestation：防重放记录的已提交 epoch | 64 | 44 |

- Go 侧 `target/material` 与 C 侧 `target/harness/kr_parser.h` 都基于同样的
  魔数独立定位锚点，保证“原始偏移”在控制平面与被测解析器之间一致。
- 锚点原始偏移在 `init` 时写入 SQLite `anchors` 表，每个样本导入时再次把
  逐样本偏移写入 `samples.anchor{1,2,3}_offset`。

## 2. 漏洞与局部修正

缺陷“密钥轮换失效”：解析器只校验 header，从不比较**密封该帧的密钥 epoch**
与 attestation 已提交 epoch，于是用**已退役旧密钥**密封的帧被当作轮换生效
而接受（重放）。

- 漏洞版 `kr_replay_vuln`：缺少该比较，陈旧帧返回判定码 **77**
  （`ROTATION_FAILURE_REPRODUCED`）。
- 修正版 `kr_replay_fixed`：在同一处补回**唯一一处** epoch 比较
  （`-DKR_FIXED`），陈旧帧返回 **78**（`STALE_KEY_REJECTED`）；正常帧两版
  均返回 0（`FRAME_ACCEPTED`），证明修正无回归。

修正严格局部化：`target/harness/kr_parser.h` 中 `KR_FIXED` 宏只包住那一个
比较，其余解析路径完全不动。

## 3. 目录结构

```
cmd/krfix/            Go CLI（init/build/import/fuzz/run/status/report/export/verify）
internal/
  material/           原始材料封存、只读保护、样本导入、三段锚点偏移
  store/              SQLite schema、样本/任务/运行/证据表、断点状态机
  runner/             libFuzzer 单文件重放、退出码分类、覆盖率引导活动
  evidence/           逐样本 JSON 报告、对比结论、tar.gz 证据包
target/
  material/gen.go     帧格式、锚点定位（Go 侧权威实现）
  harness/            libFuzzer C 源码（漏洞版 + KR_FIXED 修正版同一来源）
scripts/
  build.sh            一次编译四个 harness（fuzz/replay × vuln/fixed）
  e2e_check.sh        端到端验收脚本（含中断-恢复、防篡改）
```

## 4. 工作流

```bash
# 0) 工具链（本机无 root 时见第 8 节）
export PATH=/tmp/go/bin:/tmp/toolchain/usr/bin:$PATH

# 1) 初始化：生成并只读封存原始材料，建 SQLite 与三段锚点
krfix init

# 2) 编译 libFuzzer 四件套到 .krfix/build
krfix build

# 3) 导入确定性语料（6 个攻击 + 3 个良性样本），记录每样本原始偏移
krfix import

# 4) 可选：跑真实 libFuzzer 覆盖率引导活动，自动产出崩溃样本
krfix fuzz --phase vuln --seconds 15
#    崩溃样本可再导入并独立重跑：
krfix import --file .krfix/fuzz/vuln/artifacts/crash-xxxx --name fuzz01 --kind attack

# 5) 逐样本独立重放（漏洞版 + 修正版），可按样本/阶段过滤
krfix run
krfix run --sample atk_epoch_lag1 --phase vuln   # 只重跑一个样本的一个阶段
krfix run --redo                                  # 保留历史，强制重跑

# 6) 查看状态（时间点、退出码、判定、原始偏移）
krfix status

# 7) 逐样本报告与证据导出
krfix report --sample atk_epoch_lag1
krfix export --sample atk_epoch_lag1             # 生成 .tar.gz 证据包

# 8) 校验未修改的原始材料
krfix verify
```

## 5. 中途退出与重新进入

- 每个 `(样本, 阶段)` 是 SQLite `jobs` 表中的一行，状态机：
  `pending → running → done | interrupted | error`。
- 进程收到 `SIGINT/SIGTERM` 时通过 `signal.NotifyContext` 取消子进程；正在
  执行的作业落为 `interrupted`（强杀场景则留在 `running`）。
- 再次 `krfix run` 时，启动恢复逻辑把残留 `running` 自动改为 `interrupted`
  并重新认领，已完成的作业跳过，未完成的续跑，历史 `runs` 全部保留。
- 所有进度在 WAL 模式 + `synchronous=FULL` 下即时落盘，退出不丢证据。

## 6. 验收如何落到“具体时间点”和“原始偏移”

SQLite（`.krfix/krfix.db`）是唯一验收依据，关键列：

- 时间点：`anchors.located_at_utc`、`samples.imported_at_utc`、
  `jobs.created_at_utc/started_at_utc/finished_at_utc`、
  `runs.started_at_utc/finished_at_utc`、`evidence.captured_at_utc`，
  全部为 **UTC RFC3339 纳秒**；另存 `runs.duration_ns`。
- 原始偏移：`anchors.raw_offset`（材料级）与
  `samples.anchor1_offset/anchor2_offset/anchor3_offset`（样本级），
  即距原始材料字节 0 的字节偏移（本格式为 0 / 16 / 64）。
- 判定：`runs.exit_code / verdict_code / verdict_label`，对照
  77=漏洞复现、78=修正拒绝、0=接受。
- 证据：`evidence` 表保存每个 stdout/stderr 日志与样本副本的路径和
  SHA-256；导出包内含报告、样本与全部日志，可离线复核。

逐样本报告 `report` 的 `comparison` 字段给出修正是否确认缺陷：
攻击样本要求“漏洞版复现 + 修正版拒绝”，良性样本要求“两版均接受（无回归）”。

## 7. 未修改原始材料的保证

- `init` 把原始帧写为 `.krfix/original/original_kr_blob.bin`，权限 `0444`，
  并将 SHA-256、大小、封存时间写入 `run_meta` 与 `ORIGINAL_MANIFEST.txt`。
- 再次 `init` 拒绝覆盖；所有重放只读取 `.krfix/corpus/` 下的副本，
  永远不写原始目录。
- `verify`（以及每次 `run` 前）重新哈希并比对，任何字节或权限漂移都会
  非零退出并报告 pinned/actual 两个哈希。

## 8. 无 root 工具链准备（本机已验证）

环境默认只有 gcc 且代理不可用。可用直连 Ubuntu 源 + 本地前缀安装
clang/libFuzzer，Go 使用本地工具链，SQLite 采用纯 Go 驱动
（`modernc.org/sqlite`，无需 cgo）：

```bash
# clang 21 + libFuzzer 运行时，解压到用户目录
mkdir -p /tmp/debs /tmp/toolchain && cd /tmp/debs
APT_CONFIG=/dev/null apt-get -o Acquire::http::Proxy=DIRECT \
  -o Acquire::https::Proxy=DIRECT download \
  clang clang-21 libclang-rt-21-dev libclang-common-21-dev \
  libclang1-21 libclang-cpp21 libllvm21 llvm-21-linker-tools # 及其依赖
for f in *.deb; do dpkg-deb -x "$f" /tmp/toolchain; done
export PATH=/tmp/toolchain/usr/bin:/tmp/go/bin:$PATH

# Go 模块走直连可达的镜像
go env -w GOPROXY=https://goproxy.cn,direct
```

## 9. 测试

```bash
go test ./...                 # 单元测试：锚点偏移、判定分类、状态机、封存、对比
KRFIX_BIN=$PWD/krfix BUILD_DIR=$PWD/.krfix/build bash scripts/e2e_check.sh
```

`e2e_check.sh` 在临时目录完整走一遍：初始化/只读封存 → 导入 → 逐样本双阶段
重放 → 重入跳过 → SIGTERM 中断与恢复 → 77/78/0 判定 → 证据导出包 →
原始材料防篡改检测。

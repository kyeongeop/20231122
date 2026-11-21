# auditfix

`auditfix` 是一个“安全审计日志完整性”局部修正与复核工具，固定使用：

- Go：CLI、状态机、时钟校准、导出与校验；
- libFuzzer：逐样本解析哈希链并输出稳定结论；
- SQLite：原始证据、样本、运行与每次尝试的唯一状态源。

它面向两台设备时钟不同步、日志中存在缺失片段的场景。工具不会伪造缺失事件，而是用共享锚点校准时钟，只记录缺失区间、可见哈希边界和判定原因，并保留原始日志与全部尝试证据。

## 关键保证

- 每个攻击样本先用 SQLite 中的原始字节落盘，再通过独立 libFuzzer 进程执行。
- 每次执行都是一条不可覆盖的 `attempt`；中断后再次进入会新增尝试，不删除旧记录。
- 样本结果按固定字段和固定顺序导出，可重复执行、比较和独立复核。
- 导出包包含原始设备日志、原始样本、事件、修正段、运行配置、每次尝试的完整 stdout/stderr。
- `manifest.sha256` 固定 `manifest.json`；清单再固定包内每个文件、SQLite 快照和字段顺序。
- `verify` 会从原始日志重新计算事件与缺失段，并核对 SQLite 快照，避免只检查哈希而遗漏语义篡改。
- 相同状态重复导出是确定性的，包括 `state.sqlite`。

## 构建

依赖：

- Go 1.23+
- 带 libFuzzer / ASan / UBSan 运行时的 Clang
- 不需要系统安装 SQLite CLI 或 C SQLite 头文件，Go 侧使用纯 Go 驱动

```bash
make all
make test
```

如果工具不在 `PATH` 中，可显式指定：

```bash
make all GO=/path/to/go CLANG=/path/to/clang
```

产物：

- `build/auditfix`
- `build/auditfix_harness`

## 端到端演示

```bash
make demo
```

演示会在 `demo/` 中：

1. 导入两台设备日志：`device-b` 快 30 秒，`device-a` 缺 `seq 5-6`；
2. 导入 8 个攻击样本；
3. 第一次运行只执行 2 个样本后 `paused`；
4. 第二次运行从剩余样本继续，最终 `complete`；
5. 单独重放“时钟偏移 + 缺失片段”样本；
6. 比较首次与重放结果；
7. 导出并静态复核；
8. 用 libFuzzer 独立重跑全部样本；
9. 从 SQLite 快照恢复并核对运行。

演示结果会检查每个样本的预期分类。

## 手工流程

```bash
# 1. 导入双设备 JSONL 日志
build/auditfix case import \
  --db audit.sqlite --case-id incident-001 \
  --a device-a.jsonl --b device-b.jsonl \
  --description "device clocks are not synchronised"

# 2. 导入攻击样本目录（文件名排序决定 sample_index）
build/auditfix sample import \
  --db audit.sqlite --case-id incident-001 --dir corpus

# 3. 开始运行；--limit 可在执行 N 个新尝试后主动暂停
build/auditfix run \
  --db audit.sqlite --case-id incident-001 \
  --run-id review-001 --harness build/auditfix_harness --limit 2

# 4. 中途退出或主动暂停后继续；只会补做尚无终态结果的样本
build/auditfix resume \
  --db audit.sqlite --run-id review-001

# 5. 单独重放一个样本；会新增 attempt，不改写第一次证据
build/auditfix replay \
  --db audit.sqlite --run-id review-001 \
  --sample 04-clock-skew-missing.sample

# 6. 比较同一运行的首末尝试，或比较两个运行
build/auditfix compare --db audit.sqlite --run-id review-001
build/auditfix compare --db audit.sqlite --left review-001 --right review-002

# 7. 导出确定性复核包
build/auditfix export \
  --db audit.sqlite --run-id review-001 --out review-bundle

# 8. 同事独立复核；可选重跑所有嵌入式样本
build/auditfix verify --bundle review-bundle
build/auditfix verify --bundle review-bundle \
  --rerun --harness build/auditfix_harness

# 9. 恢复导出时的精确 SQLite 状态
build/auditfix restore --bundle review-bundle --db restored.sqlite
```

真实 Ctrl-C / SIGTERM 也会进入暂停路径。当前子进程输出会以 `interrupted` 尝试保存；若进程被硬杀，则遗留的 `running` 尝试会在下次进入时标记为 `interrupted` 并重新执行。

## 局部修正语义

日志事件包含设备本地时间、序号和哈希链：

```text
sha256("AFX-AUDIT-1\n" + device + "\n" + seq + "\n" + time_ns +
       "\n" + kind + "\n" + anchor_id + "\n" + subject +
       "\n" + payload_sha256 + "\n" + prev_hash + "\n")
```

设备 B 的时钟偏移取共享锚点 `(b.time - a.time)` 的中位数，随后只对 `corrected_time_unix_ns` 做派生修正，原始 `time_unix_ns` 不变。

当同一设备出现 `seq` 缺口时：

- 原始事件不改写；
- 写入一条 `corrections`，记录缺失范围、左边界哈希、右侧 `prev_hash`、校准后时间和判定原因；
- 若右侧 `prev_hash` 指回左侧可见哈希，缺口为 `gap_sealed`；
- 若无法与可见链衔接，则标记为 `gap_unresolved`，整体链状态不再视为已验证。

这是一种诚实的“局部修正”：修复时间轴和证据索引，不补造无法证明的审计记录。

## 攻击样本格式

libFuzzer 目标读取 UTF-8 行式样本：

```text
AFXS1
D<TAB>a<TAB>1<TAB>1763772001000000000<TAB>anchor<TAB>beacon-standard<TAB>clock.sync<TAB><payload_sha256><TAB><prev_hash><TAB><record_hash>
D<TAB>b<TAB>1<TAB>1763772011000000000<TAB>anchor<TAB>beacon-standard<TAB>clock.sync<TAB><payload_sha256><TAB><prev_hash><TAB><record_hash>
```

`a` / `b` 分别代表 `device-a` / `device-b`。Harness 不因攻击样本本身而崩溃，而是输出稳定的单行结果：

```text
AUDITFIX_RESULT {"schema":"auditfix.harness.v1",...}
```

当前分类：

- `OK`
- `MALFORMED`
- `CHAIN_BREAK`
- `ANCHOR_MISMATCH`
- `MISSING_SEGMENT`
- `CLOCK_SKEW`
- 运行级 `TIMEOUT` / `CRASH`

组合问题按严重度输出，`findings` 同时保留所有发现。演示中的时钟偏移与缺失段样本会同时保留 `CLOCK_SKEW` 和 `MISSING_SEGMENT`。

## 导出包

```text
review-bundle/
  manifest.json        # schema、行数、字段顺序、文件摘要、运行配置
  manifest.sha256      # detached manifest 摘要
  case.json
  run.json
  events.jsonl
  corrections.jsonl
  evidence.jsonl
  evidence/            # 原始日志字节
  samples.jsonl
  samples/             # 原始攻击样本字节
  attempts.jsonl       # 所有尝试、输出哈希/路径和规范化 result_json
  attempts/            # 每次尝试的完整原始 stdout/stderr
  state.sqlite         # 导出时 SQLite 快照
  review.md            # 人工复核摘要与步骤
```

所有 JSONL 行使用固定结构字段顺序。`verify` 会：

- 校验 detached manifest 摘要与清单内每个文件；
- 按结构体重新序列化每行并逐字节比较，检查字段顺序和规范编码；
- 检查事件、修正、证据、样本、尝试的全局顺序；
- 从 `evidence/` 原始日志重算事件、时钟偏移和缺失段；
- 校验样本字节、尝试绑定关系、stdout/stderr 哈希及完整输出；
- 交叉核对 `state.sqlite` 与导出 JSON；
- 拒绝未列入清单的文件和符号链接。

## SQLite 持久化

核心表：

- `cases`、`events`、`corrections`
- `evidence_blobs`：原始日志不可变副本
- `samples`：原始样本不可变副本
- `runs`：运行配置、harness 哈希、超时与 fuzz 参数
- `attempts`：每次执行的时间、退出码、信号、stdout/stderr、规范化证据摘要

SQLite 使用 WAL、外键和 `synchronous=FULL`。尝试在启动前先写入 `running`，完成后在同一数据库中更新为终态。

## 测试

```bash
make test
```

包括：

- Go 单元测试：哈希、日志解析、时钟校准、缺失段、导出确定性、篡改拒绝、恢复顺序；
- libFuzzer 构建；
- 端到端集成：暂停/续跑、独立重放、导出、静态复核、全样本重跑、SQLite 恢复。

## 安全边界

导出包用于防误改和可复核，不是身份签名。若需证明“由谁导出”，应在上层对 `manifest.sha256` 做独立签名或时间戳。缺失段中无法证明的内容不会被补造；复核者仍应结合外部审计源判断缺口原因。

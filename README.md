# idorfix — 多租户 IDOR 检测局部修正工具

面向多租户系统的 IDOR（不安全直接对象引用）局部修正工作台。核心场景是两台设备
时钟不同步时，把无法重建的时间区间显式标记为**缺失片段（missing fragment）**，并让
每个攻击样本都能单独重跑、比较、导出和重新载入。

技术栈固定为：

- **Go**：检测引擎、CLI、状态机与全部业务逻辑
- **libFuzzer**：通过 cgo + `c-archive` 接入的模糊测试引擎
- **SQLite**：WAL 模式的本地工作区数据库（纯 Go 驱动 `modernc.org/sqlite`）

## 工具链

仓库不假设系统已安装 Go/clang，本机使用已就位的本地工具链，激活方式：

```bash
source .envsetup/env.sh
```

该脚本把 Go 1.27、clang-21（含 libFuzzer）加入 `PATH`，并配置离线模块缓存。

## 构建

```bash
source .envsetup/env.sh
make build          # 产出 bin/idorfix
make fuzz           # 产出 build/fuzz/idorfix_fuzzer（libFuzzer）
make test           # 全部 Go 单元测试 + 原生 fuzz 冒烟
```

## 工作区与命令

所有命令都以单个样本为操作单位，数据库默认是当前目录的 `idorfix.db`，可用
`--db PATH` 覆盖。

```bash
idorfix init                                   # 初始化工作区
idorfix import --file testdata/samples/x.json  # 入库（计算内容哈希、去重）
idorfix list                                   # 按插入顺序列出样本
idorfix run --sample SAMPLE_ID                 # 单样本执行一次
idorfix replay --sample SAMPLE_ID              # 再执行一次并与上次比较
idorfix runs --sample SAMPLE_ID                # 查看该样本的全部运行
idorfix compare --a RUN_ID --b RUN_ID          # 任意两次运行逐项对比
idorfix export --sample S --run R --out DIR    # 导出可独立复核的证据包
idorfix verify --bundle DIR                    # 复核证据包（校验和+重算判定）
idorfix reload --bundle DIR                    # 重新载入，保留字段与顺序
idorfix recover                                # 把残留 RUNNING 行标记为 INTERRUPTED
```

## 缺失片段如何产生

1. 每个设备带 `offset_ns`（设备时钟相对参考时钟的偏移）和 `uncertainty_ns`
   （校准后仍无法消除的残余误差）。
2. 事件时间减去偏移后落到统一参考时间线，并按时间稳定排序。
3. 当相邻且来自不同设备的两个事件，其残余不确定性窗口发生重叠时，该区间内的真实
   先后顺序无法证明，即生成一个合并后的 `MissingFragment`。
4. 若关键证据落在缺失片段内、且没有正向 IDOR 信号，引擎给出 `INCONCLUSIVE` 而不是
   草率地判 `BENIGN`，避免时钟问题掩盖真实攻击。

判定规则（版本号 `rules-2026.11.0`，随导出记录留存）：

- `IDOR-T1`：请求了外租户资源 → `CONFIRMED_IDOR`
- `IDOR-V1`：非 admin 角色跨租户 → 叠加为 `VERTICAL_IDOR`
- `IDOR-H1`：同租户内访问他人资源 → `HORIZONTAL_IDOR`
- `GAP-001`：证据落入时钟缺失片段

## 中途退出与重新进入

运行采用 **write-ahead 状态机**：任何分析开始前，先写入 `PENDING` 行，再转
`RUNNING`。

- 收到 `SIGINT`/`SIGTERM`：当前运行显式落为 `INTERRUPTED`，证据与原因保留。
- 进程被 `SIGKILL`/崩溃：`idorfix recover` 检查 PID 存活性，把死进程残留的
  `PENDING/RUNNING` 行标记为 `INTERRUPTED`；仍存活的 PID 不会被误回收。
- 重新进入只需再次 `idorfix run --sample ...`，产生新的 attempt，旧记录不被覆盖。

## 证据导出与同事独立复核

`export` 生成一个自包含目录：

| 文件 | 作用 |
|---|---|
| `bundle.json` | 完整记录，字段顺序固定 |
| `sample.json` | 可单独重跑的样本输入 |
| `verdict.json` | 引擎输出（判定、发现、缺失片段） |
| `review.md` | 人工复核表，含检查清单 |
| `manifest.json` | 每个文件的 SHA-256 与自校验和 |

复核同事拿到目录后，无需原数据库即可：

```bash
idorfix verify --bundle DIR
```

该命令会重算所有校验和、校验 bundle 的字段顺序契约，并对嵌入样本**重新执行一次
检测引擎**，确认结果与导出判定一致。任何字节或字段顺序篡改都会导致非零退出码。

## 字段与顺序保证

- 持久化与导出统一走 `internal/exchange` 的保序规范化编码：结构体按声明顺序输出，
  map 按键排序，去除空白。
- `AssertFieldOrder` 在导入、复核、重新载入时按结构体契约逐字段校验顺序，字段
  缺失、多余或乱序都会被拒绝。
- `reload` 直接读取导出的 `sample.json` 并走标准幂等导入，因此往返后字段、顺序与
  内容哈希保持不变；重复载入同一内容会被识别为跳过而非报错。

## 模糊测试

- libFuzzer：`./build/fuzz/idorfix_fuzzer internal/fuzz/corpus`，种子语料就是
  `testdata/samples` 下的样本。引擎检测两类缺陷：畸形输入导致 panic，以及同一
  样本两次判定不一致（非确定性）。
- 原生 Go：`go test ./internal/fuzz -fuzz=FuzzTarget`，与 libFuzzer 共用同一个
  `Target` 函数，复现器可以互换。

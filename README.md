# apiskew

`apiskew` 是一个面向“API 版本权限差异”的局部修正工具。它围绕一个重复对象，把两台设备的时钟偏移作为攻击面，用 libFuzzer 搜索 `v1` 与 `v2` 允许性不一致的样本，并用 Go 重放器独立复核后写入 SQLite。

每个攻击样本都可以单独重跑、比较和导出。发现、重跑、暂停和离开都会留下持久化证据；重新进入后从 SQLite 检查点和 libFuzzer 语料继续。导出包不依赖原数据库，包含固定字段顺序、全部尝试证据、校验和及复核命令。

## 技术组成

- Go：CLI、确定性样本解码、权限评估、SQLite 事务、重跑/比较/修复计划/导出/离线复核。
- libFuzzer：`fuzz/api_diff_fuzzer.cc` 使用与 Go 相同的场景规则搜索 `v1.allow != v2.allow`，只把原始命中的 24 字节样本原子写入 findings 目录。
- SQLite：保存会话、重复对象快照、样本顺序、每次运行证据、事件日志和中断检查点。导出包另带固定列顺序的 `records.db`。

默认场景是一张重复发票对象：`replica-a` 是规范修订 7，`replica-b` 是旧修订 5 且已删除。`v1` 按“同步时间 + 设备时钟偏移”选择副本；`v2` 按规范修订、规范时间、副本顺序选择。设备 B 向前偏移时，`v1` 会选中已删除的旧副本并拒绝，而 `v2` 允许，形成可复现的权限差异。

## 构建

前置条件：Go 1.26+、带 libFuzzer/AddressSanitizer 运行时的 Clang。

```bash
go build -o build/apiskew ./cmd/apiskew
scripts/build-fuzzer.sh build/apiskew_fuzz
```

如果 `clang++` 不在 PATH 中，可指定：

```bash
CLANGXX=clang++-21 scripts/build-fuzzer.sh build/apiskew_fuzz
```

也可以使用 `make build`、`make fuzzer`、`make test`。

## 快速开始

```bash
./build/apiskew --db apiskew.db init --name local-review

./build/apiskew --db apiskew.db discover \
  --fuzzer ./build/apiskew_fuzz \
  --seconds 15 \
  --max-findings 500

./build/apiskew --db apiskew.db status
```

`discover` 正常完成或按下 Ctrl+C 后会把会话置为 `paused`，findings 与 corpus 保留在默认的 `artifacts/sessions/<session>/fuzz`。重新进入：

```bash
./build/apiskew --db apiskew.db resume
./build/apiskew --db apiskew.db discover --seconds 15
```

已入库内容按 SHA-256 跳过；`--max-findings` 限制本次新增样本数，同时作为 libFuzzer 单次运行的原始 finding 文件上限，因此重复进入不会卡在同一批文件，也不会无限占用磁盘。

单样本重跑、与 libFuzzer 交叉验证、比较和生成局部修正计划：

```bash
./build/apiskew --db apiskew.db replay \
  --sample s0001 --engine go+libfuzzer --repeat 3

./build/apiskew --db apiskew.db compare --sample s0001

./build/apiskew --db apiskew.db fix \
  --sample s0001 --out artifacts/fix-s0001.json

./build/apiskew --db apiskew.db export \
  --sample s0001 --out review-s0001
```

`fix` 会独立执行三次 Go 评估，验证已存证据没有漂移，并使用“规范化时钟 + 规范修订排序”的 v1 解析器重算。输出包含 `before_v1_allow`、`after_v1_allow`、`v2_allow` 和 `verified`。

## 导出与独立复核

```bash
./build/apiskew --db apiskew.db export --out review-bundle
cd review-bundle
sha256sum -c SHA256SUMS
apiskew verify-bundle .
apiskew verify-bundle . --sample s0001
```

导出目录：

- `records.jsonl`：每条样本一行，字段顺序固定；这是记录字段契约的权威顺序。
- `records.csv`：与 JSONL 相同的字段和行序，便于表格审阅。
- `attempts.jsonl`：每次重跑的固定字段摘要，按样本和尝试号排序。
- `evidence/<sample>-a<attempt>.json`：每次尝试的完整证据，包括重复对象快照、两个设备时钟、v1/v2 决策、选中副本、ACL、原因和样本哈希。
- `records.db`：SQLite 记录快照；`SELECT ... ORDER BY ordinal` 可重新载入并复现顺序。
- `scenario.json`：本次会话的唯一重复对象和两台设备配置。
- `manifest.json`、`SHA256SUMS`、`REVIEW.md`：字段契约、文件哈希和复核步骤。

`verify-bundle` 不访问原数据库。它会校验全部校验和、JSONL 顶层字段顺序、CSV 头与行序、SQLite 列与行序、证据文件哈希，再用 Go 对每条样本重新评估并比对决策和修正计划。任一字段、顺序或哈希变化都会失败。

## 数据与恢复语义

- 样本 `ordinal` 在单事务内单调分配，随后所有列表查询使用 `ORDER BY ordinal ASC`。
- 每次重跑新增一个 `attempt`，不覆盖历史；`attempts.jsonl` 和 `evidence/` 保留全部尝试。
- `discover_started`、`discover_interrupted`、`discover_checkpoint`、`sample_imported`、`sample_replayed`、`fix_plan_generated` 写入事件表。
- 收到 Ctrl+C/SIGTERM 后，先立即把会话置为 `paused`，再用持久化目录中的 findings 执行批量导入；即使进程在导入期间再次被强杀，findings 仍可在下次 `discover` 导入。
- SQLite 使用 WAL、外键和 `synchronous=FULL`；批量导入一个事务提交。
- 产物重新载入时保持 `records.jsonl` 字段顺序、`ordinal` 行序、CSV 列序和 SQLite 查询顺序。

## 样本格式

攻击输入固定 24 字节，小端：

| 偏移 | 长度 | 字段 |
| ---: | ---: | --- |
| 0 | 4 | magic `ASK1` |
| 4 | 1 | schema version `1` |
| 5 | 1 | actor role：0 owner、1 editor、2 viewer、3 outsider |
| 6 | 1 | action：0 read、1 update、2 delete |
| 7 | 1 | bit0 tenant match、bit1 request device B |
| 8 | 4 | device A skew，毫秒，int32 |
| 12 | 4 | device B skew，毫秒，int32 |
| 16 | 8 | 保留，当前忽略 |

Go 解码器与 C++ libFuzzer 目标对 magic、版本、枚举范围和差异条件保持一致。`make test` 在提供 `APISKEW_FUZZER` 时会逐样本验证两侧判定一致。

## 自定义重复对象

默认配置可直接使用。需要替换对象或修订时：

```bash
./build/apiskew --db apiskew.db init \
  --config examples/scenario.json --name custom
```

场景文件会被严格解码（拒绝未知字段），其规范 JSON 哈希写入每个会话和导出包。

## 验证

```bash
go test ./...
APISKEW_FUZZER=$PWD/build/apiskew_fuzz go test ./internal/fuzzrun
```

测试覆盖二进制样本编解码、v1/v2 差异与修复验证、SQLite 重开后的字段/顺序、批量导入、导出/离线复核、篡改检测，以及 libFuzzer 与 Go 的判定一致性。

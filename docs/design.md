# 压缩流截断处理：可暂停流水线设计

## 1. 领域场景

两台设备（`DeviceA=101`、`DeviceB=202`）围绕同一个重复对象
（`object_id`）周期性上报观测记录。设备时钟未同步：B 相对 A 存在
固定毫秒偏移。每条记录在链路上以 flate 压缩帧承载，采集端可能因掉电、
缓冲区截断而在任意字节处中断。

流水线必须做到：

1. 解析任意（含畸形、截断）输入而不崩溃，并给出稳定的错误分类。
2. 处理过程可在检查点安全暂停、落盘中间状态，重开产物后继续。
3. 一次连续运行与“暂停后恢复”的运行产生字节一致的最终报告。
4. 资源不足时沿固定降级阶梯退化，而不是直接失败，并保留证据。
5. 产物重新载入后字段与顺序保持不变，导出包可由同事独立复核。

## 2. 线格式（`internal/stream`）

```
magic "TST1" | frame... | EOF(0x7E)
frame = crc32(uvarint) | type(1) | flags(1) | deviceID(uvarint)
        | seq(uvarint) | tsMillis(uvarint) | payloadLen(uvarint) | payload
```

`crc32`（IEEE）覆盖 `type..payload`。每第 3 帧置 `FlagCheckpoint`，
作为唯一允许暂停的边界。截断分类共 7 类，字符串值稳定、直接入库：

| 类 | 触发条件 |
| --- | --- |
| `BAD_MAGIC` | 魔数不匹配 |
| `TRUNCATED_HEADER` | 头部 varint 不完整 |
| `TRUNCATED_PAYLOAD` | 声明载荷超出采集长度 / 缺 EOF |
| `CHECKSUM_MISMATCH` | 帧 CRC 不匹配 |
| `DECOMPRESS_FAILED` | flate 解压失败 |
| `BAD_JSON_ENCODING` | 载荷 JSON 非法 |
| `UNKNOWN_FRAME_TYPE` | 帧类型字节非法 |

解析器对 varint 溢出做了显式防护（fuzz 曾发现 int64 溢出导致切片越界，
见提交历史中的回归用例）。

## 3. 时钟不同步对账（`internal/reconcile`）

- 匹配键是 `(object_id, seq)`，**绝不使用墙钟时间配对**。
- 参考时间线固定为设备 A（其偏移为 0）。
- B 的时钟偏移取配对时间差的**中位数**，对少量坏点鲁棒。
- `Fingerprint` 对解析器可见的帧偏移、CRC、原始载荷与 EOF/错误分类做
  SHA-256；同一采集在任何进程中指纹一致，是恢复时的防篡改依据。

## 4. 可暂停处理（`internal/pipeline`）

处理循环逐帧推进，只在检查点帧暂停：

1. `Start` 解析两路采集，写入原始字节与解析结果证据，创建 `runs` 行。
2. `Process` 从最新检查点恢复 `ProcessingState`，先校验输入指纹。
3. 每帧计入资源预算；到达检查点时把状态以确定性 JSON 落盘并记录哈希。
4. 暂停请求只在检查点生效，因此恢复后不会重复或跳过帧。
5. `Finalize` 完成对账并持久化报告；报告结构不含 `run_id`，保证不同
   运行在相同输入下哈希相同。

`ProcessingState` 字段顺序固定（见 `store.ProcessingState`），
`json.MarshalIndent` 配合有序 struct 与 map，使重载入后字节一致。

## 5. 资源不足与降级（`internal/resource`）

四级阶梯，压力取 token、字节、堆占用三者最大比例：

| 级别 | 阈值 | 行为 |
| --- | --- | --- |
| 0 NORMAL | <50% | 全量保留，累加指标 |
| 1 REDUCED | >=50% | 不再保留载荷语义，累加器改为计帧 |
| 2 SAMPLED | >=75% | 每 `SampleEvery` 帧处理一帧，提高检查点频率 |
| 3 BAILOUT | >=100% | 在下一检查点停止并持久化部分状态 |

每次级别变化产生一条 `degradation_events`；恢复时通过
`Monitor.Replay` 还原已消耗量与级别，避免重复记录历史事件。

## 6. SQLite 证据模型（`internal/store`）

单一数据库文件，WAL 模式、外键开启、strict 类型，表结构带
`schema_version` 元信息：

- `runs`：运行状态、预算、消耗、截断分类、最终降级级别。
- `checkpoints`：检查点状态 JSON 及其 SHA-256。
- `evidence`：原始采集、解析结果、检查点哈希、报告哈希、前后差异。
- `degradation_events`：降级轨迹。
- `reports`：确定性报告 JSON 及其 SHA-256。

驱动使用纯 Go 的 `modernc.org/sqlite`，无需系统 libsqlite。

## 7. 导出与独立复核（`internal/export`）

导出为确定性 tar：文件名排序、固定 mtime、每文件 SHA-256 写入
`MANIFEST.json`，整包哈希写入同名 `.sha256` sidecar。

复核入口：

- `truncstream verify-bundle B.tar`：仅依赖 Go 标准库，重算清单哈希，
  任何字节翻转都会被拒绝。
- `truncstream verify-artifact A.sqlite`：重开产物，重算检查点、证据、
  报告哈希，并用原始采集重放解析器比对解析证据。

## 8. Fuzzing

- Go 原生 fuzz（`go test -fuzz`）覆盖解析器、构建往返、对账确定性、
  导出包篡改检测。
- 真正的 libFuzzer 路径：`fuzz/cmd/bridge` 通过 cgo
  `//export TSTParse` 把生产解析器导出为 C ABI，clang
  `-fsanitize=fuzzer` 链接 `libclang_rt.fuzzer` 驱动，见
  `scripts/build_libfuzzer.sh` 与 `fuzz/libfuzzer_harness.c`。

# LFI 证据可复核流水线

把本地文件包含（Local File Inclusion）取证结果固化为可复核流程：围绕
**旧格式 v1** 与 **新格式 v2** 两个版本快照，将攻击输入、触发位置、权限判断、
日志证据四类信息按 `correlation_id` 对齐，存入 SQLite 供审计；被截断的记录
保留有效前缀与原始字节；单对象异常不影响其余对象；运行结束清理临时状态。

技术栈固定为 **Go + libFuzzer + SQLite**（SQLite 驱动为纯 Go 的
`modernc.org/sqlite`，libFuzzer 通过 cgo 桥接，见 `fuzz/libfuzzer`）。

## 目录结构

```
cmd/lfi-review/      流水线 CLI（双快照 -> SQLite -> 复核报告）
cmd/lfi-query/       只读查询工具（证据表 + review_pairs 视图）
internal/model/      归一化证据模型
internal/parse/      v1/v2 双格式解析、截断判定与容错恢复（fuzz 目标）
internal/pipeline/   快照发现、逐对象容错、临时状态与清理
internal/storage/    SQLite schema、证据表、复核视图、WAL/旁路文件清理
internal/fuzzshim/   libFuzzer 入口对应的 Go 适配层
fuzz/libfuzzer/      cgo 桥 + LLVMFuzzerTestOneInput（libfuzzer build tag）
fuzz/corpus/         种子语料（含截断与畸形输入）
snapshots/v1_legacy/ 旧格式快照（含一条被截断记录、一条畸形记录）
snapshots/v2_current/ 新格式快照（同一事件的完整版本）
docs/REVIEW.md       复核流程、字段映射与 SQL 示例
```

## 快速开始

```bash
make build          # 编译全部 Go 包
make test           # 单元测试（解析/存储/流水线，含容错与清理断言）
make review         # 跑两个快照，输出报告，数据库落 artifacts/review.sqlite
make query          # 查看证据表与跨快照对照视图
make fuzz-go        # Go 原生 fuzz（无需 C 工具链）
make libfuzzer      # clang + libFuzzer 构建（需设置 CLANG_DIR）
make libfuzzer-run  # 运行 libFuzzer，结果输出到 fuzz/artifacts/
```

临时库模式（结束即删除数据库与工作目录）：

```bash
go run ./cmd/lfi-review -db "" -v
```

## 关键行为

- **双格式兼容**：v1 扁平 JSON 与 v2 版本化嵌套信封归一到同一 `evidence` 表。
- **截断保留**：严格解析报 EOF 类错误时判定为 `truncated`，用 token 级扫描
  恢复有效前缀，原始字节写入 `raw_object`；普通语法错误判为 `malformed`。
- **异常隔离**：每个对象独立 读取→解析→入库，单点失败只记账不中断。
- **可复核对照**：SQLite 视图 `review_pairs` 按 `correlation_id` 全外连接
  新旧两份记录，截断差异与权限/日志差异同屏可见。
- **临时清理**：临时工作目录、临时 SQLite 及其 `-wal`/`-shm` 在结束时删除。

详细字段映射、截断恢复机制与复核 SQL 见 `docs/REVIEW.md`。

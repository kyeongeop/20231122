# tve — 可暂停的模板变量逃逸处理流水线

围绕一组**极限参数**（模板填充、值长度 4KiB、重复 2000 次、输出预算）
组织一个重复对象（同一模板 × N 条记录），处理过程可暂停、可恢复，
恢复后结果与不间断参考运行逐比特一致。技术栈：**Go + libFuzzer + SQLite**。

## 结构

- `internal/escape` — 模板变量逃逸引擎（`{{name}}` → HTML 转义），硬限制 +
  软降级（值截断 / 输出预算截断 / 未知变量 / 未闭合变量），每个降级事件
  都带模板内原始偏移。
- `internal/store` — cgo 直连系统 `libsqlite3.so.0`（容器无 sqlite3 头文件，
  手工声明稳定 C ABI）。表：`jobs` / `checkpoints` / `batches` / `events` / `material`。
- `internal/runner` — 可暂停运行器。检查点序列化 `crypto/sha256` 运行态
  （`encoding.BinaryMarshaler`），恢复后继续处理。
- `internal/material` — 原始材料：确定性生成（含 HTML 特殊字符、未闭合 `{{`、
  非法 UTF-8），只读保存（`0444` + `.sha256` 边车 + DB 内 blob），永不修改。
- `cmd/tve` — CLI：`gen-material` / `run` / `resume` / `verify` / `events`。
- `fuzz` — libFuzzer 标准入口 `LLVMFuzzerTestOneInput`（Go c-archive 导出）+
  回放驱动；`internal/escape/fuzz_test.go` 为 Go 原生 fuzz 入口。

## 处理流程

```sh
go build -o tve ./cmd/tve
./tve gen-material -seed 7                      # 生成并只读保存原始材料
./tve run -repeat 2000 -template-pad 512 -value-len 4096 \
        -max-value 1024 -batch 100 -pause-after 500 -budget 4000000
#   -> PAUSED（检查点 seq=1, next=500）
./tve resume -job 1   # -> RESOURCE-EXHAUSTED（检查点 seq=2, next=854）
./tve resume -job 1   # -> 降级模式继续 -> COMPLETED
./tve verify -job 1   # 验收
./tve events  -job 1  # 关键证据：UTC 时间戳 + 原始偏移
```

## 资源不足与降级路径

- **软降级**（引擎内）：值超 `MaxValueBytes` 截断、输出超 `MaxOutputBytes` 截断、
  未知变量置空、未闭合 `{{` 按字面量输出 —— 全部记 `degraded` 事件。
- **资源不足**（运行器）：会话输出字节超 `OutputBudget` → 保存检查点、记
  `resource-exhausted` 事件、状态置 `exhausted` 并停止。
- **降级恢复**：从 `exhausted` 恢复时进入降级模式（值长缩为 1/8、禁用超大
  `big` 变量、会话预算重置），继续处理直至完成。

## 验收标准（`tve verify`，落到具体时间点与原始偏移）

1. 原始材料未修改：DB blob、磁盘只读副本、`jobs.material_sha` 三者 SHA-256 一致。
2. 前后结果一致：暂停/恢复后的最终哈希 == 不间断参考运行哈希
   （证据：检查点 `seq` 与 `saved_utc`，如 `seq=3 saved_utc=2026-11-22T07:36:23.81154107Z`）。
3. 批次证据与参考逐行一致，且无缝覆盖记录区间 `[0, Repeat)`。
4. 时间戳链：所有事件时间为可解析的 UTC RFC3339Nano 且单调不减；
   `paused` 时刻严格先于 `resumed` 时刻（报告打印两者及其差值）。
5. 每条事件的 `raw_offset` 都落在原始材料 `[0, 1048576)` 区间内。
6. 关键证据存在：至少包含降级或资源耗尽事件。

## 模糊测试

```sh
# Go 原生 fuzz（本容器已验证：30s / 1900 万 execs 无失败）
go test ./internal/escape/ -fuzz=FuzzRender -fuzztime=30s

# libFuzzer（需要 clang；无 clang 时用回放驱动 sh fuzz/run_replay.sh）
go build -buildmode=c-archive -o fuzz/tve_fuzz.a ./fuzz/fuzztarget
clang -fsanitize=fuzzer,address fuzz/tve_fuzz.a -o fuzz/tve-fuzz
./fuzz/tve-fuzz fuzz/corpus -max_total_time=60
```

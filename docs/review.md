# 同事独立复核指南

本指南假设你只拿到一个导出包（tar + `.sha256` sidecar）以及本仓库源码，
不共享任何运行时状态。

## 1. 环境

- Go 1.27+（仅复核 bundle 哈希时，标准库即可）。
- 可选：clang 21（含 `libclang_rt.fuzzer`），用于复跑 libFuzzer。

## 2. 校验导出包

```bash
go run ./cmd/truncstream verify-bundle artifacts/demo-full/review-bundle.tar
cat artifacts/demo-full/review-bundle.tar.sha256
sha256sum artifacts/demo-full/review-bundle.tar
```

预期：命令输出 `OK ... every manifest sha256 matches`，且 sidecar 中的
`bundle_sha256` 与 `sha256sum` 完全一致。

## 3. 重开 SQLite 产物

```bash
go run ./cmd/truncstream verify-artifact artifacts/demo-full/resumable.sqlite
```

该命令会：

1. 核对 `schema_version`。
2. 重算每条 `checkpoints.state_json` 的 SHA-256，与 `state_sha256` 比对。
3. 重算每条 `evidence.content` 的 SHA-256，与 `content_sha256` 比对。
4. 取出原始采集 `RAW_CAPTURE_A/B`，重新调用 `stream.Parse`，与入库的
   `PARSE_RESULT_A/B` 做归一化比对。

## 4. 核对暂停/恢复等价性

demo 同时产生 `baseline.sqlite`（一次跑完）与 `resumable.sqlite`
（检查点暂停、重开后继续）。两者的 `reports.report_sha256` 必须相同；
差异证据存于 `evidence` 表 `BEFORE_AFTER_DIFF` 行，`reports_equal=true`
且 `differences=[]`。

可用任意 SQLite 工具（本仓库 CLI 不依赖系统 sqlite3）查询：

```sql
SELECT run_id, state, parse_error_class, degrade_level, last_checkpoint_seq
  FROM runs;
SELECT level, reason, detail FROM degradation_events ORDER BY id;
SELECT kind, content_sha256 FROM evidence ORDER BY id;
```

## 5. 复跑模糊测试

```bash
# Go 原生引擎
go test ./internal/stream/ -fuzz=FuzzParse -fuzztime=30s
go test ./internal/reconcile/ -fuzz=FuzzReconcileDeterminism -fuzztime=20s
go test ./internal/export/ -fuzz=FuzzBundleRoundTrip -fuzztime=20s

# 真正的 libFuzzer 引擎（需 clang）
bash scripts/build_libfuzzer.sh
fuzz/bin/truncstream_fuzz fuzz/corpus_libfuzzer -max_total_time=60
```

## 6. 篡改实验

对 tar 内任意文件翻转一个字节后再次执行 `verify-bundle`，命令必须以
非零状态退出并报告 `hash mismatch` 或 `size mismatch`。对 SQLite 中
检查点状态做任何修改后执行 `verify-artifact`，同样必须失败。

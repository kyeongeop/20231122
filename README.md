# 压缩炸弹资源耗尽验证（bombverify）

重建“压缩炸弹 → 资源耗尽”验证流程：攻击输入经配额受限的解压器处理，
每个环节（攻击输入 → 触发位置 → 权限判断 → 日志证据）落入 SQLite 证据库，
导出为定序 JSONL，同事可独立重载并逐字段复核。

技术栈：Go 1.23+、libFuzzer（clang 19 `libclang_rt.fuzzer` + Go `-d=libfuzzer`
插桩）、SQLite（`modernc.org/sqlite`，纯 Go）。

## 组件与证据链对应

| 环节 | 位置 |
| --- | --- |
| 攻击输入构造 | `internal/runner/scenarios.go`（5 个场景，含缺失片段异常） |
| 容器格式与配额解压 | `internal/decomp/`（BMB1 格式，输出字节/展开比/块数配额） |
| 触发位置捕获 | `internal/decomp/decomp.go` `Error`（runtime.Caller 记录 file:line/func） |
| 权限判断 | `internal/runner/policy.go`（`decompress.execute` 动作，allow/deny 落库） |
| 日志证据 | `internal/runner/audit.go`（JSONL 审计日志，每行 sha256，记录链摘要入库） |
| 证据存储 | `internal/evidence/`（SQLite `evidence` 表 + `meta.field_order`） |
| 定序导出/重载 | `internal/evidence/io.go`（20 个字段固定顺序，乱序拒绝导入） |
| libFuzzer 入口 | `fuzz/main.go`（`LLVMFuzzerTestOneInput` → `decomp.Decompress`） |

## 场景

- `ok`：合法容器（对照组）
- `missing_fragment`：块引用片段表外的字典 id（缺失片段异常）
- `zip_bomb`：8 MiB 零字节的 flate 流，超出 `MaxOutputBytes`
- `empty_input`：空输入
- `oversize_input`：超过 `MaxInputBytes` 的超大输入

## 复现

```sh
export PATH="$HOME/go/bin:$PATH" GOPATH="$HOME/gopath"
go build -o bin/bombverify ./cmd/bombverify
./bin/bombverify scenario all                 # 生成攻击输入并跑全部场景
./bin/bombverify scenario --subject intern --deny missing_fragment   # 权限拒绝路径
./bin/bombverify export                       # 导出 artifacts/evidence.jsonl
./bin/bombverify reload --source-db artifacts/evidence.db            # 重载并校验
```

## 独立复核

1. 重载产物：`bombverify reload --in artifacts/evidence.jsonl --db /tmp/review.db`
   —— 字段缺失、多余或顺序不符会被拒绝。
2. 逐条比对：`reload --source-db artifacts/evidence.db` 对每条记录做内容摘要比对。
3. 日志核对：证据行的 `log_digest` 是该次运行全部审计日志行摘要的链式 sha256，
   可用 `artifacts/audit.log` 重算验证。
4. 直接查库：`sqlite3 artifacts/evidence.db 'select * from evidence;'`
   （字段顺序见 `meta` 表的 `field_order`）。

## 模糊测试（libFuzzer）

```sh
./fuzz/build_fuzzer.sh                        # 需要 clang 工具链，见脚本内路径
./fuzz/fuzzbomb fuzz/corpus -max_total_time=60 -artifact_prefix=artifacts/crashes/
```

种子语料在 `fuzz/corpus/`（含全部场景输入、空输入、截断头、随机数据）。
最近一次运行：31 秒约 295 万次执行，无崩溃，峰值 RSS 52 MiB。

## 测试

```sh
go test ./...
```

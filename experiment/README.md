# YAML 别名资源耗尽 · 可回放实验

技术栈: Go 1.23 · Go 原生覆盖率模糊测试(libFuzzer 式) · SQLite(mattn/go-sqlite3)。

## 结构

- `internal/snap/v1` — 快照 v1(无防护): 别名展开无任何限额, 炸弹输入导致指数级内存耗尽
- `internal/snap/v2` — 快照 v2(加固): 同一语法 + `Limits`(输入字节/别名数/展开节点/深度)
- `internal/ledger` — SQLite 步骤账本: 每一步记录输入(sha256+字节数)、状态(JSON)、结果
- `internal/corpus` — 实验对象集; `bomb.qzx` 使用未知扩展, 由内容嗅探识别
- `cmd/exp` — 分阶段 Runner: init → parse-v1 → parse-v2 → 顺序变更 → 重复提交 → 证据 → 清理

## 回放

```sh
cd experiment
go build -o bin/exp ./cmd/exp
# 1) 模糊测试(约 45s, 证据输出到 /tmp/yamlexp-fuzz-log)
go test -run=FuzzParse -fuzz=FuzzParse -fuzztime=45s ./internal/snap/v2/
# 2) 完整实验(证据写入 ../artifacts/evidence, 临时目录自动清理)
./bin/exp -evidence ../artifacts/evidence -fuzz /tmp/yamlexp-fuzz-log
```

## 判定口径

- v1 在 256MiB `RLIMIT_AS` + 6s 超时的子进程中运行, 崩溃即资源耗尽证据
- 顺序变更: 固定种子打乱语料重跑 v2, 按内容哈希比对结果, 判定 `order_invariant`
- 重复提交: 同内容再次提交, 账本去重计数, 判定 `dedup_repeat` + 幂等结果一致
- 异常续跑: 空对象注入 panic, `recover` 后循环继续, 后续对象全部有步骤记录

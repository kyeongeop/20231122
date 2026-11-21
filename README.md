# permaudit — 容器镜像权限审计（可暂停处理流程）

对容器镜像 layer（tar）做权限审计，支持暂停/恢复、资源耗尽降级、
证据留存与原始材料保全。技术栈：Go + libFuzzer（Go 原生 fuzz 引擎）+ SQLite。

## 结构

- `cmd/permaudit` — CLI：`run / report / compare / verify / snapshot / check-original`
- `cmd/genimage` — 生成确定性测试镜像（覆盖全部规则 + 3 个 1MiB 大文件）
- `internal/audit` — 权限分类纯函数、可暂停扫描器、原始 tar 头解析
- `internal/store` — SQLite：runs / checkpoints / findings / events 四张表
- `scripts/acceptance.sh` — 端到端验收

## 关键机制

- **可暂停**：`run -pause-after N` 处理 N 个条目后落检查点并以退出码 3 暂停；
  再次执行同一 `-run-id` 即从 SQLite 中最新检查点的**原始偏移**恢复。
- **极限参数 + 重复对象**：`-checkpoint-every 1`（每条目一检查点）、
  `-mem-budget 1`（立即触发降级）下对同一镜像跑 round1..3，结果互相比对。
- **资源不足降级**：内容哈希预算耗尽后切换为仅元数据模式，记录 `degrade`
  事件（含时间点与偏移），运行状态记为 `completed_degraded`。
- **证据**：findings/events/checkpoints 均带 UTC 时间戳（RFC3339Nano）与
  tar 原始字节偏移；`verify` 用原始偏移重新读 512 字节头块复核条目名。
- **原始材料**：`snapshot` 以只读方式保存 `artifacts/original/<sha256>.tar`
  与 MANIFEST；`check-original` 复核哈希未被修改。

## 验收

```sh
bash scripts/acceptance.sh
```

逐项检查：基线 vs 暂停/恢复结果一致（compare）、多轮确定性一致、
所有 finding 的原始偏移可复验（verify）、原始材料哈希未变
（check-original），并打印落到具体时间点与原始偏移的证据报告。

## 测试

```sh
go test ./...
go test ./internal/audit/ -run '^$' -fuzz FuzzClassifyMode -fuzztime 15s
go test ./internal/audit/ -run '^$' -fuzz FuzzHeaderName -fuzztime 15s
```

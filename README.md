# truncstream

面向“两台时钟不同步设备围绕同一重复对象上报压缩流”的可暂停截断处理
流水线。技术栈固定为 **Go + libFuzzer + SQLite**。

## 能力

- 截断感知解析：7 类稳定错误分类，畸形输入不 panic（fuzz 守护）。
- 可暂停处理：仅在检查点帧暂停，SQLite 持久化中间状态，重开继续。
- 前后等价：连续运行与暂停/恢复运行的报告 SHA-256 完全一致。
- 资源降级：NORMAL → REDUCED → SAMPLED → BAILOUT 四级，全程留证。
- 字段与顺序：状态/报告 JSON 字段顺序固定，重载后字节一致。
- 独立复核：确定性 tar 导出包 + 双入口校验命令（bundle / artifact）。

## 目录

```
cmd/truncstream/          CLI：demo、verify-bundle、verify-artifact、corpus
internal/stream/          线格式、截断分类解析器、记录生成
internal/reconcile/       时钟偏移中位数估计与确定性对账
internal/store/           SQLite schema、检查点/证据/降级/报告持久化
internal/pipeline/        可暂停处理循环、前后报告比较
internal/resource/        预算与四级降级阶梯
internal/export/          确定性 tar 导出与独立校验
fuzz/cmd/bridge/          cgo 导出，供 libFuzzer 驱动生产解析器
fuzz/libfuzzer_harness.c  libFuzzer C 入口
scripts/build_libfuzzer.sh  构建 libFuzzer 二进制
docs/                     设计文档与复核指南
```

## 快速开始

```bash
# 端到端：基线 vs 暂停/恢复，比较哈希，导出复核包
go run ./cmd/truncstream demo -dir artifacts/demo -frames 27 -suspend-after 8

# 资源不足降级路径
go run ./cmd/truncstream demo -dir artifacts/demo-budget -tight-budget -suspend-after -1

# 独立复核
go run ./cmd/truncstream verify-bundle artifacts/demo/review-bundle.tar
go run ./cmd/truncstream verify-artifact artifacts/demo/resumable.sqlite

# 测试与 fuzz
go test ./...
go test ./internal/stream/ -fuzz=FuzzParse -fuzztime=30s

# libFuzzer（需要 clang，见脚本顶部 CLANG_ROOT 变量）
bash scripts/build_libfuzzer.sh
fuzz/bin/truncstream_fuzz fuzz/corpus_libfuzzer -max_total_time=60
```

详见 `docs/design.md` 与 `docs/review.md`。

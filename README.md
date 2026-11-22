# 验证码重放检测 · 可暂停处理流程

围绕两台时钟不同步设备的验证码事件流，实现可暂停/恢复的重放检测管线，
技术栈固定为 **Go + libFuzzer + SQLite**（纯 Go 驱动 `modernc.org/sqlite`，
无需系统 SQLite 库）。

## 能力

- 基于参考时钟（`observed_at + offset_ms`）的重放、过期、未知码、时钟倒挂判定。
- 序列号缺口与参考时钟跳变两类“缺失片段”证据，跨分段边界不重复、不遗漏。
- 预算暂停、确定性故障注入、检查点恢复；分段运行与一次性运行结果严格等价。
- 内存上限触发 SQLite 持久化降级路径，输出与内存路径一致并留下降级标记。
- 原始事件 SHA-256、决策、缺口、检查点全量落库；导出带校验和的 JSONL 复核包。
- libFuzzer 通过 c-shared 接入，持续校验“分段/快照往返 ≡ 一次性执行”不变量。

## 目录

```
cmd/replayctl        CLI：run / export / verify / compare / gen-fixture
internal/model       事件、配置、判定与缺口类型
internal/detect      纯函数检测状态机（可 fuzz、可快照恢复）
internal/store       SQLite schema、证据写入、检查点、降级查询
internal/pipeline    分段编排、故障注入、夹具生成
internal/export      JSONL + manifest 复核包导出
internal/review      校验和验证、JSONL 重载、前后运行比对
fuzz/export          Go c-shared 导出层
fuzz/libfuzzer       libFuzzer C++ harness
testdata             签入的夹具输入
docs/DESIGN.md       设计说明
docs/REVIEW.md       独立复核手册
```

## 快速开始

```
make test   # 全部单元与集成测试
make demo   # 生成 artifacts/review 下四组可复核运行
make fuzz   # libFuzzer 会话
```

不使用 make 时可直接运行 `scripts/demo.sh` 与 `scripts/run_libfuzzer.sh`。

## CLI 示例

```
replayctl gen-fixture --out testdata/fixture.json
replayctl run --input testdata/fixture.json --db evidence.sqlite --max-events 3
replayctl run --input testdata/fixture.json --db evidence.sqlite   # 恢复续跑
replayctl export --db evidence.sqlite --out review-bundle
replayctl verify --bundle review-bundle
replayctl compare --before bundle-a --after bundle-b
```

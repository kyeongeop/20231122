# 协议状态机模糊测试（可回放实验）

技术栈：Go（状态机 + 编排器）+ libFuzzer/clang（差分模糊）+ SQLite（证据库）。

## 结构

- `exp/proto/` — 会话协议状态机的两个版本快照：v1（有缺陷）与 v2（已修复），
  以及线格式解码器（`[op:1][len:1][payload]*`，截断记录会被标记为对照）。
- `exp/fuzzlib/` + `exp/harness/fuzz.c` — libFuzzer 入口，调用 Go 差分执行；
  发现 v1/v2 分歧时按签名去重并保存 crash 样本（上限 32 个），不中断模糊循环。
- `exp/store/` — SQLite 证据库（`runs` / `steps` / `verifications` 三张表）。
- `exp/cmd/fuzzexp/` — 编排器：逐对象、逐版本执行并记录每一步的输入、状态、
  结果；随后做回放、乱序、重复提交三类验证；异常被 recover 后继续处理其余对象；
  结束时删除临时目录并关闭数据库。
- `scripts/run_experiment.sh` — 端到端：构建 → 模糊 → 记录/验证 → 报告。

## 复现

```sh
./scripts/run_experiment.sh        # FUZZ_SECONDS=60 可调模糊时长
```

## 证据（保留在 artifacts/）

- `artifacts/evidence.sqlite` — 每一步输入/状态/结果与全部验证结论。
- `artifacts/crashes/crash-*` — 触发 v1/v2 分歧的最小样本（按分歧签名去重）。
- `artifacts/report.md` — 分歧清单、验证结论、截断对照对象的逐步记录。

## 最近一次运行结论

- 41 秒约 1390 万次执行，发现 32 类 v1/v2 分歧（v1 在 OPEN 前 SEND 会 panic、
  任意状态可 CLOSE；v2 均已修复）。
- 37 个对象全部处理完毕，12 次异常被恢复且未中断后续对象。
- 回放 74/74 `REPLAY_OK`；乱序 `ORDER_SENSITIVE`；重复提交 `DUPLICATE_DETERMINISTIC`。
- 截断对照记录按预期被拒绝（`TRUNCATED_REJECTED`，状态不变）。

注：libFuzzer 的覆盖率反馈只覆盖 C 桥接层（Go 代码不经 SanitizerCoverage），
分歧检测在 Go 侧完成；如需覆盖率引导可后续接入 `-fsanitize-coverage` 回调。

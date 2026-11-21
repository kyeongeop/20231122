# libFuzzer 目标

`parser_fuzz.c` 用 C 复刻 Go 解析器的线协议与三段锚点，供 clang 的
libFuzzer + AddressSanitizer + UndefinedBehaviorSanitizer 插桩。

## 构建

```bash
./build.sh
```

- `parser_fuzz_hardened`：带溢出守卫，期望长时间模糊测试零告警/零崩溃。
- `parser_fuzz_vulnerable`：额外启用 `-fsanitize=unsigned-integer-overflow`，
  在历史无检查运算上复现 uint32 回绕。

## 运行

```bash
./run.sh                                   # hardened，默认 60s
./parser_fuzz_vulnerable ../evidence/corpus/CASE-A2.bin -runs=1
```

## 已复现的 UBSan 发现

| 案例 | 源码位置 | 运算 |
|------|----------|------|
| CASE-A1 | parser_fuzz.c:49 | `536870912 * 9` uint32 回绕 |
| CASE-A2 | parser_fuzz.c:56 | `4294967280 + 32` uint32 回绕 |
| CASE-A3 | parser_fuzz.c:57 | `8 + 4294967289` uint32 回绕 |

完整输出见 `../evidence/crashers/ubsan-vulnerable.log`；hardened 的 60 秒
模糊测试统计见 `../evidence/crashers/hardened-fuzz-60s.log`。

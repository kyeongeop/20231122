# 协议超时状态机 — 可回放实验报告

SQLite 证据库: `/home/hj/userfeedback3/uid6-0050/artifacts/experiment.db`

## 一、自动结论

| 场景 | 步数 | 接受 | 拒绝 | 重复 | 未知扩展 | 终态 | 重放一致 | 结论 |
|---|---|---|---|---|---|---|---|---|
| baseline_recovery | 6 | 6 | 0 | 0 | 0 | CLOSED | true (mismatch=0) | PASS |
| unknown_extension_control | 7 | 6 | 1 | 0 | 1 | CLOSED | true (mismatch=0) | PASS |
| reorder_check | 6 | 2 | 4 | 0 | 0 | CLOSED | N/A | PASS |
| duplicate_submit | 5 | 4 | 1 | 1 | 0 | CLOSED | N/A | PASS |

### 失败时的可执行后续操作

- 无失败项。若后续出现失败，报告将在此给出对应 SQLite 排查与重跑命令。

## 二、人工确认清单

- [ ] 用 `go run ./cmd/dbquery` 核对 runs=4、events=24、replay_checks=13 且 mismatch=0。
- [ ] 确认 unknown_extension_control 中 X_PING 被拒绝（accepted=false）且流程仍到达 CLOSED。
- [ ] 重跑 `go test ./...` 与 `make fuzz`，确认无回归、无 fuzz 崩溃。
- [ ] 抽查 evidence/trace_*.json，确认每一步的输入、后继状态与状态哈希均已落盘。
- [ ] 对照 evidence/report.md 第三节，人工确认乱序与重复提交的拒绝原因符合预期。

## 三、逐步证据（输入 / 状态 / 结果）

### baseline_recovery — CONNECT -> SUBMIT -> TIMEOUT -> RECOVER -> ACK -> CLOSE

| seq | 输入 kind | msg_id | 接受 | 重复 | 结果原因 | 后继状态 | 状态哈希(前16位) |
|---|---|---|---|---|---|---|---|
| 1 | CONNECT |  | true | false | connected | CONNECTED | 12607a54d8eb6917 |
| 2 | SUBMIT | m-100 | true | false | request sent | REQUEST_SENT | d0627d6516d84d55 |
| 3 | TIMEOUT |  | true | false | timed out | TIMED_OUT | e54bdbfc9dc7ddc9 |
| 4 | RECOVER |  | true | false | recovery started | RECOVERING | d0fcddc0b425f204 |
| 5 | ACK | m-100 | true | false | acknowledged | ACKED | c3cc852e64da7515 |
| 6 | CLOSE |  | true | false | closed | CLOSED | 9bb5c19075f34220 |

### unknown_extension_control — valid recovery with unknown extension X_PING injected before ACK

| seq | 输入 kind | msg_id | 接受 | 重复 | 结果原因 | 后继状态 | 状态哈希(前16位) |
|---|---|---|---|---|---|---|---|
| 1 | CONNECT |  | true | false | connected | CONNECTED | 12607a54d8eb6917 |
| 2 | SUBMIT | m-200 | true | false | request sent | REQUEST_SENT | d0647d64dc5bd3ea |
| 3 | TIMEOUT |  | true | false | timed out | TIMED_OUT | 7cf0b9ac65db0d0d |
| 4 | RECOVER |  | true | false | recovery started | RECOVERING | c2707742c91a7232 |
| 5 | X_PING | ext-1 | false | false | unknown extension: X_PING | RECOVERING | ff4e584e17063526 |
| 6 | ACK | m-200 | true | false | acknowledged | ACKED | 5a50533998bd91c5 |
| 7 | CLOSE |  | true | false | closed | CLOSED | 3896f55414a8f897 |

### reorder_check — TIMEOUT(seq3) delivered before SUBMIT(seq2); state guard and stale-seq guard both reject the inversion

| seq | 输入 kind | msg_id | 接受 | 重复 | 结果原因 | 后继状态 | 状态哈希(前16位) |
|---|---|---|---|---|---|---|---|
| 1 | CONNECT |  | true | false | connected | CONNECTED | 12607a54d8eb6917 |
| 3 | TIMEOUT |  | false | false | TIMEOUT only valid in REQUEST_SENT | CONNECTED | 5e882cedf1c12ec2 |
| 2 | SUBMIT | m-100 | false | false | stale seq 2 <= last 3 | CONNECTED | 422db0b220b50ddc |
| 4 | RECOVER |  | false | false | RECOVER only valid in TIMED_OUT | CONNECTED | 19225521c2b1a04a |
| 5 | ACK | m-100 | false | false | ACK only valid in REQUEST_SENT or RECOVERING | CONNECTED | e4652701a19e08d1 |
| 6 | CLOSE |  | true | false | closed | CLOSED | 16dc79894896e7b5 |

### duplicate_submit — same msg_id submitted twice; second occurrence is a duplicate no-op

| seq | 输入 kind | msg_id | 接受 | 重复 | 结果原因 | 后继状态 | 状态哈希(前16位) |
|---|---|---|---|---|---|---|---|
| 1 | CONNECT |  | true | false | connected | CONNECTED | 12607a54d8eb6917 |
| 2 | SUBMIT | m-300 | true | false | request sent | REQUEST_SENT | 86773046000924de |
| 3 | SUBMIT | m-300 | false | true | duplicate message id: idempotent no-op | REQUEST_SENT | f703e37ee8cdea1e |
| 4 | ACK | m-300b | true | false | acknowledged | ACKED | 4865f4592065b0d6 |
| 5 | CLOSE |  | true | false | closed | CLOSED | b8800ef75311f208 |


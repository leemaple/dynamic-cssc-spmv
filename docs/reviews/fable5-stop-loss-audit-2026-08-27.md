# Fable 5 止损审计与处置 — 2026-08-27

## 性质与证据边界

本文记录一次外部模型咨询及项目方处置，不是实验结果、注册锚点、
dispatch 权限或发表授权。

- 咨询渠道：AIGoCode 已登录账户的 Anthropic-compatible API。
- 实时模型 ID：`claude-fable-5`。该 ID 存在于账户的实时模型列表，
  但在当时公开文档的常用模型表中未列出。
- 推理设置：adaptive thinking，high effort。
- 第一轮：输入 2,453 tokens，输出 12,227 tokens。
- 纠错轮：输入 913 tokens，输出 4,675 tokens。
- 未记录、显示或写入任何 API key。

## 送审问题

评审包覆盖论文贡献边界、数学不变量、14 个候选、30 个 paired units、
有限语料成功规则、F1-M、Day1/Day2/R4 证据边界及当前 HOLD。另要求审稿人
主动寻找沉没成本陷阱，并回答：核心 Idea 是否值得继续、哪些实验缺陷可能
使结果失效、当前治理是否过度、Day1A 超时后如何止损，以及从当前状态到
可投稿的最短关键路径。

## 第一轮结论及不能直接采纳之处

第一轮给出 `CONDITIONAL PASS`：认为动态、版本绑定、可审计的 CSSC SpMV
维护层具有研究价值，但建议在继续之前进行性能 profiling。

第一轮同时产生了几项与冻结设计冲突的建议，不能进入项目：

1. 要求 worker 记录真实 F1-M mask digest，并在 replay 中重新采样后比较相同
   digest。真实 mask 使用 CSPRNG 且一次性 reserve-before-sample；重新采样不应
   相同，保存并重放 mask 还会扩大披露面。这一建议在密码学语义上不成立。
2. 把确定性的 Day1A/Day1B 策略模拟与 primitive accounting 当成恶意 Cloud 的
   proof-of-execution。冻结威胁模型是 static semi-honest，worker 本来就不执行
   OpenFHE 或采样真实 mask；要求 malicious proof 超出 claim。
3. 建议把 15/15 正效应改成 13/15、把 10,000 次分类稳定改成 95% bootstrap
   CI。冻结规则是有限语料的保守充分条件，不是总体显著性检验；失败有预注册
   fallback，不能在看到结果后放宽成功定义。
4. 把 9-rho synthetic diagnostic 与 30 个真实 paired units 作线性时间外推，
   没有执行结构依据。
5. 把当前日期写成 2025 年，并给出建立在该错误日期上的四至六周日程。

## 纠错轮裁决

在收到上述反证后，Fable 5 保持 `CONDITIONAL PASS`，但明确修订如下：

- **撤回** replay 同一随机 mask digest 的要求。
- **撤回** malicious worker proof-of-execution 门禁。
- **撤回**把 15/15 改成 13/15 以及总体 bootstrap CI 的建议。
- 将额外 zero-query `window_attestation` 降为 defense-in-depth；如果现有连续
  cardinality rows、完整窗口覆盖与 same-replay controller registry binding 已
  经验证，则它不是 P0。
- 保留一个条件性问题：必须确认实现中的更新成本分母确实是 accepted raw-event
  group，而不是 window、SET、query 或 wall-time 加权。若实现与冻结定义不一致，
  是 P0；若一致，只需补充说明。
- 不再从 9-rho diagnostic 线性推算 30-unit 时间。
- 认为项目当前**条件性不是在白费时间**；真正会浪费时间的是在未解释超时前继续
  dispatch formal Day1A 或继续堆叠与 claim 无关的治理层。

## 项目方处置

外部意见是 advisory，只有与仓库事实及冻结 claim 一致的部分才采纳。

### 采纳

1. 暂停 production invocation issuer / repository adapter 的继续扩张，先完成
   Day1A 性能根因诊断。
2. 在当前任务记录的 `total job <= 300 min` formal-launch 操作门槛下，run
   `33040816357` 已客观超时，因此不得据此启动 formal 21-shard Day1A。该 300
   分钟值目前是操作门槛；仓库 workflow 自身的 hard timeout 是 355 分钟，二者
   不得混称。
3. 保留当前 run 继续完成 replay/guard，仅作为 NON-ADMISSIBLE 诊断，不取消、
   不上传为正式证据。
4. 立即核对 group-weighted denominator 的实现与序列化证据。
5. 在 profiling 结论前不新增与论文 claim 无关的 schema、receipt 或 ledger 层。

### 拒绝

- 不让 worker 自报 F1-M frames。
- 不重放或保存真实随机 mask 以追求相同 digest。
- 不放宽 15/15、15%、Pareto 或相邻 rho 的冻结 headline 规则。
- 不把 deterministic partitions 包装成总体随机样本或频率学置信区间。
- 不依据 9:30 的数量比例估算真实语料运行时间。

## 新出现的高概率根因

只读静态 profiling 发现主运行与独立 replay 不对称：

- `scripts/run_day1_suite.py` 对高 `rho` 使用从 `rho=1` 派生的 exact query-linear
  rescaling；
- `scripts/replay_day1_shard.py` 虽验证并记录
  `query_scaling_source_rho_fraction`，却对全部九个 `rho` 重新调用完整
  `evaluate_causal_cell`。

如果动态反馈环证实这一点，replay 会把本应由 `rho=1` 精确派生的高-rho 单元
重新全量计算，解释了 step 6 长时间无进展。它同时是性能缺陷和生产/独立重放
路径不对称缺陷；修复必须保持输出字节完全相同，并由回归测试证明高-rho replay
复用与生产相同的 exact linearity seam。

## 加权分母复核结果

Fable 5 纠错轮保留的唯一条件性 estimand 问题已经由代码与测试关闭：

- 预注册明确定义 `update_count` 为 phase 内 accepted raw-event groups 数量；
- T2 同一 group 的零、一个或两个 SET 全部计入同一更新分母；
- `publication_statistics._record_cost` 用 `update_count` 分别归一化 update primitive
  totals 与 update serialized-byte totals；
- `test_t2_realized_set_cardinality_is_separate_from_stats_update_denominator` 证明
  `realized_set_count` 不会替代 accepted-group count；
- `test_byte_cost_uses_the_exact_decimal_megabits_per_second_conversion` 证明最终
  `C(rho,b)` 暴露的是 `selected_update_bytes_per_accepted_event_group`。

2026-08-27 的低优先级定向复核为 `2 passed`。因此 headline estimand 是冻结的
**group-weighted** 成本，不是逐 SET、逐 window、逐 query 或 wall-time 加权；这不是
当前 P0。

## 未来 72 小时的最多五个动作

1. 等待并保存 run `33040816357` 的最终 replay/guard 日志与步骤时长。
2. 建立秒级、确定性、可失败的 replay call-count 回归环。
3. 用该反馈环验证高-rho replay 重算假设，并比较生产/重放派生字节。
4. 若证实，仅做语义保持的 replay 对称性修复；全套相关测试与 Ruff 通过后重新
   评审是否需要新的 source/registration anchor，绝不静默替换 S1/S2。
5. 核对 group-weighted denominator；随后才决定恢复 adapter、重新诊断或转向
   methodology/negative-result fallback。

## 当前 Go / No-Go

| 决策 | 状态 | 条件 |
|---|---|---|
| 继续论文 Idea 与方法写作 | GO | 不写经验优势，不越过 HOLD |
| 继续当前 diagnostic 至自然结束 | GO | 只读、NON-ADMISSIBLE |
| 启动 formal Day1A | NO-GO | 先解释并修复/处置运行时间门槛 |
| 启动 Day1B | NO-GO | 语料、adapter、Day2、TRACE 等 HOLD 未关闭 |
| 放宽 headline 成功规则 | NO-GO | 冻结规则不得事后更改 |
| 立即停止整个项目 | NO | 目前存在可检验的性能缺陷假设与 methodology fallback |

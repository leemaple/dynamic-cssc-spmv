# Paper Idea / Mathematical Consistency Gate Packet — 2026-08-27

你是本项目的只读“论文 Idea / 数学一致性”发表门禁审稿人。请独立审查下面的同一份冻结评审包；不要改文件/代码，不要运行或 dispatch 实验，也不要把计划中的实验当成已完成证据。

请严格按以下格式回复：
第一行只写 PASS 或 AMEND。
随后分 P0 / P1 / P2；每条包含：位置或概念、问题、为什么影响论文、最小修正。若某级没有问题写“无”。
最后给出：① novelty 边界是否诚实；②公式/协议是否自洽；③在没有经验结果时可否称“已可投稿”；④下一步最关键的三个动作。
P0=阻止继续作为论文规范或会产生错误实验；P1=投稿前必须修；P2=表述/清晰度改善。不要因为措辞偏好给 P0/P1。

【冻结评审包】
题目方向：Dynamic CSSC SpMV。目标不是发明新的 HE 原语或静态 CSSC，而是把静态 CSSC 扩展成一个“版本绑定、可变矩阵、可审计”的隐私保护 SpMV 维护层，并用预注册、因果 held-out 实验评价固定策略。

1. 静态基础与边界
- 静态 CSSC 的列组/移位思想是已有基础，不作为新颖性。
- 非 2 次幂宽度 w 的规范 rotation/add 抽象节点数写为 floor(log2 w)+popcount(w)-1；它不是 2 的幂子块个数。
- 冻结整数边界：BFVRNS，ring dimension 8192，t=65537，每行至多4096项，|A_ij|<=7，|x_j|<=1；B=4096*7=28672，2B=57344<t，故全部组件先在 Z_t 合并后存在唯一 centered lift。此结论不替代 mixed-circuit 噪声门禁。

2. 版本化原子发布
- 状态 S^(v) 把矩阵组件、ColumnIndex、OutputPlan、容量/ledger 元数据绑定为一个版本。
- 候选状态先 Maintain，再 Validate；仅 Validate=1 时整体 Commit，否则保持 S^(v)，禁止“新矩阵+旧映射/计划”部分可见。
- Publication Window 内所有查询读取同一不可变 v，事件顺序固定为 SET* -> TICK -> QUERY*。

3. 查询重排与私有 OutputPlan
- 对组件 k 的物理 lane p，以版本化全局列 g_(v,k,p) 构造 x~_(v,k,p)=x_g；padding/tombstone/tail 为0，明确禁止按局部槽位或列号取模。
- 私有映射 Pi_v:(k,b,p)->i 或 bottom；Gamma_i^(v)={(k,b,p):Pi_v=i}，h_i=|Gamma_i|。
- Client B 恢复：h=0 输出0；h=1直接 centered lift；h>1 对 Gamma 中全部贡献先 mod t 求和，再一次 centered lift。由此统一重叠、拼接、隐式零。
- 完整 Pi/RowMap 由 Client A 持有并交给 Client B，但不交给 Cloud；Cloud 只拿 d_v=SHA-256(CanonicalJSON(Pi_v))，每个请求、share、mask 绑定同一 d_v，拒绝跨版本/计划拼接。

4. F1-M overlap-only 零和掩码
- 仅 h>1 时在 Z_t 采 r_1...r_(h-1)，令 r_h=-sum r_j mod t；Cloud 返回 z_j+r_j，Client B 合并仍得 sum z_j。
- h=0/1 不生成随机零和 mask；固定形状需要的 encrypted-zero dummy 是另一成本类别。
- 一次性绑定 beta=(q,v,d_v,component,output-block)。SQLite ledger 必须 Reserve(beta) 先于 SampleMask(beta)；重复绑定拒绝，reserve 后崩溃也视为已消费。主张不覆盖仓库回滚、DB复制、跨设备协调或DB攻破。

5. strong delta
- A^(v)=A_base^(v)+A_seg^(v)，overflow 用 Cloud 可执行固定宽度 segment，逻辑行合并仍由 Client B 私有计划决定。
- c=128=2^7，4096 slots 可放32段；每段固定 rotation-add：u^(r+1)=u^r+Rot(u^r,2^r), r=0...6，再以公开 leader mask 保留段首。c=128 是预冻结协议点，不声称全局最优。

6. 候选与成本
- 14 fixed records = 13 selectable references + 1 non-selectable ablation。references 包括 padding-reuse、mini-cssc-delta、strict-local-repack、5个 reserved-slack beta、periodic-repack windows 1/4/16/64、strong segmented delta；client-lane delta capacity=128 仅 ablation。
- 每个 cell 只用 tuning prefix 选固定 k*=argmin C_tune，规范 ID 唯一 tie-break；从该候选连续状态进入 held-out，禁止重置或 held-out 重选。offline oracle 仅诊断。
- Day1A 只产因果 primitive counts；Day2 OpenFHE 1.5.1 用14个 measurement blocks 的中位数得到 theta_p。成本 C(rho,b)=T_u_compute+8B_u/(b*10^6)+rho(T_q_compute+8B_q/(b*10^6))；B 来自实际规范序列化，不按密文数量猜。

7. 因果评价
- 三真实语料 x 两语义(T1累计 cap7；T2 K=32768 sliding window，先 expiry 后 admission) x 五个 source-entity hash partitions = 30 paired units。
- 每 unit 目标131072 accepted groups，连续10/30/60 warm/tune/held 切分，每个候选维持自己的连续 Strategy Snapshot。
- confirmatory family 仅 T2、freshness=0.1s，共15 units；T1和1.0s只做预注册 secondary。
- 主基线 periodic-repack/windows=1。delta=(C_recompress-C_selected)/C_recompress，要求每个 unit C_recompress>0、15/15 delta>0、median delta>=15%、selected 对13 references 均 Pareto non-dominated、全部正确性/来源/重放门禁通过；最终还要至少一对相邻 rho 同时通过。
- 分区非随机样本，因此只报告 per-unit、median/IQR、描述性 block-resampling sensitivity，不包装成总体置信区间或p值。Day2 10000次共用 block ordinal 的重采样须全部保持 winner/effect/Pareto 分类才释放 headline。

8. 证据状态
- S1=febedea78c88ed779171cedc5dab4be097061a1f；S2=f158aa7697b8b47a7704c4a4a2028bf6c7c080c4，S2只安装 registration anchor。
- registration evidence 已成功。当前仅有一条 exact-S2、NON-ADMISSIBLE 的 Day1A 9-cell 诊断 shard 在运行；没有可采信经验结果。
- Day2、真实语料获取/冻结、30-unit Day1B、R4 端到端正确性、最终分析/论文正文尚未完成。
- 因此当前文稿只是一份详细 Idea/技术规范，绝不能写成“实验已证明”或“已可投稿”。

请基于以上内容裁决。

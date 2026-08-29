---
title: "Dynamic CSSC SpMV：论文核心 Idea 与完整技术路线"
subtitle: "面向可变稀疏矩阵同态矩阵—向量乘法的版本绑定维护、私有重构与可审计评估"
author: "项目技术说明（Route C 边界稿；正式策略结果未产生）"
date: "2026-08-30"
lang: zh-CN
numbersections: true
---

# 阅读提示

本文解释这篇论文“到底想解决什么、核心 idea 是什么、为什么需要这些机制、公式如何连接到实现，以及最后怎样用实验回答问题”。它不是结果论文的替代稿，也不把尚未完成的实验写成结论。

截至 2026-08-30，项目已经完成 Route A 的工程冻结链，也已经得到一次性资格运行的终局裁决。最终候选 `baefc8cc183816c51ce42573bafde8178173044d` 经 ChatGPT Pro 与 ZCode GLM-5.3 Max 独立终审均无 P0/P1；Fable 5 的 Terminal 调用因 provider 返回 `403 账户余额不足`而只记录为 unavailable，不构成裁决。该候选经 PR #39 合入 tree-identical 的 Experiment Source Snapshot S1 `ee58627bb5752c6ac1ee2c5132c6574f9cb66552`。S1 main CI `33258436732` 与 exact-main PRE-S1 `33259569284` 均成功；前者记录 `2403 passed, 2 skipped`，后者执行固定 OpenFHE 1.5.1 ordinary/strong 两路真实 smoke、`583 passed`、Ruff 全绿且 artifact 数为 0。描述性 registration run `33259894587` 成功后，只增加 registration data anchor，形成 Evidence-Freeze Snapshot S2 `c7ff6820d9323f1850c1c5c57fd9070db88db120`；S2 main CI `33260167517` 也成功。

唯一允许的一次 NON-ADMISSIBLE qualification run `33261434612` 随后从 exact S2 启动，但在冻结的 45 分钟 computational deadline 到达时，q2 independent replay 仍在运行，q5 combined guard 从未开始。外部 controller 因此只取消该 exact run；最终状态为 `completed/cancelled`，只留下一个一天保留、永久不可进入论文结果的 q1 handoff。没有 q5 guard、没有 q6 record、没有不可序列化 dispatch capability，也没有任何 formal artifact。按预注册，Route A 已明确选择 **Route C**：不得重跑 qualification，不得启动 acquisition 或 16 个 formal shards，不得把 q1/q2 的运行片段包装成策略性能结果。终态复核还发现 GitHub 为两个未真正执行的下游 cancelled jobs 返回了 `completedAt` 早于 `startedAt` 一秒的反常元数据；controller 因此 fail-closed 拒绝终态读取。这一控制器审计缺口没有造成假 GO，也不是资格失败原因；在本次冻结尝试中不会通过修改 S1 后偷换身份再跑一次。

# 一句话概括论文 idea

这篇论文不是发明一种新的同态加密算法，也不是重新发明静态 CSSC 稀疏格式。它提出的是一个围绕静态 CSSC 的**可变矩阵维护层**：

> 把每次更新后的逻辑矩阵、物理 CSSC 组件、查询重排元数据、输出重构计划、一次性掩码和成本证据全部绑定到同一个不可变版本；在此基础上比较“立即重压缩、保留空隙、局部增量、周期折叠”等维护策略，回答在不同查询/更新比和新鲜度约束下，什么时候增量维护优于每次全量重压缩。

核心不在某一个数据结构，而在四个原本容易断开的环节被闭合到同一条因果链：

1. **状态闭合**：逻辑矩阵和物理布局必须属于同一版本；
2. **查询闭合**：查询重排必须使用该版本真实的全局列编号，不能把列号当作槽位号；
3. **结果闭合**：多个组件的返回值必须由私有 `OutputPlan` 按逻辑坐标重排、相加或拼接；
4. **证据闭合**：候选选择、运算计数、OpenFHE 实测常数、通信字节和最终论文结论必须来自同一冻结行为与可重放工件。

# 研究问题为什么存在

## 静态 CSSC 解决了什么

设稀疏矩阵为

$$
A\in\mathbb{Z}_t^{m\times n},
$$

查询向量为

$$
x\in\mathbb{Z}_t^n,
$$

目标是计算

$$
y = Ax \pmod t.
$$

静态 CSSC 会对稀疏坐标排序、把非零元素装入适合 BFV 批处理槽位的矩形、保存 `Value`、全局 `ColumnIndex` 和 `RowMap`，并通过查询重排和旋转—求和减少对零元素的无效同态计算。

静态情况下，矩阵的非零结构不变，所以物理位置和逻辑坐标之间的映射可以长期复用。问题在于，真实系统中的矩阵可能发生插入、删除和修改：

$$
A^{(0)}\xrightarrow{U_0}A^{(1)}\xrightarrow{U_1}A^{(2)}\longrightarrow\cdots,
$$

其中 $U_v$ 是第 $v$ 个更新集合。

一次插入不只改变一个值。它可能占用预留空位、产生溢出组件、改变行排序、改变 `ColumnIndex`、改变 `RowMap`，并改变最终结果如何从多个密文返回值中恢复。于是，简单地“更新 Value 数组”并不足以保持函数正确。

静态 CSSC substrate 可以概括为

$$
\operatorname{CSSC}(A)=(\mathrm{Value},\mathrm{ColumnIndex},\mathrm{RowMap},\mathrm{ChunkPlan}).
$$

设一个 chunk 的物理高度为 $h$、宽度为 $w$，列主序 lane 可以写成

$$
\ell=ah+r,
\qquad
0\le a<w,
\qquad
0\le r<h,
$$

并要求

$$
hw\le S_{\mathrm{eff}}=4096.
$$

对宽度 $w\ge1$ 的 chunk，冻结的纸面 rotation/add 节点数为

$$
f(w)=\left\lfloor\log_2w\right\rfloor
+\operatorname{popcount}(w)-1.
$$

例如 $f(7)=4$，而 $f(8)=3$。仓库没有照搬静态 CSSC 伪代码中对非二次幂存在歧义的 set-bit 分支，而使用实现相同归约语义、具有同一抽象计数的 stored-power/prefix DAG。它既不是论文 Algorithm 4 的字面 trace，也不被宣称为 HElib `totalSum` 的逐行 trace；这个修正用于兼容正确性，不是新的聚合算法，也不等价于已经测得的 wall time 或 noise cost。

若共有宽度 $w_1,\ldots,w_M$ 的 chunks，则抽象的段内计数为

$$
N_{\mathrm{rot}}^{\mathrm{intra}}
=N_{\mathrm{add}}^{\mathrm{intra}}
=\sum_{k=1}^{M}f(w_k),
$$

而每个 chunk 还需要一个 plaintext selection mask：

$$
N_{\mathrm{ptmask}}=M.
$$

跨 chunk 的实际加法数必须由 executable DAG 决定，不能只根据纸面表格猜测。

## 朴素解法为什么可能太贵

最安全的朴素策略是在每次发布边界都重建整个 CSSC：

$$
L^{(v+1)}=\operatorname{CompressCSSC}\!\left(A^{(v+1)}\right).
$$

它的优点是查询路径干净；缺点是每次更新都可能重新编码、加密和传输大量布局对象。另一类策略保留旧 base，把变化放入 delta 或 overflow：

$$
A^{(v)}=A_{\mathrm{base}}^{(v)}+A_{\mathrm{delta}}^{(v)}.
$$

这样减少更新侧发布成本，却会增加查询侧的组件数量、同态运算、返回密文、客户端重排以及掩码成本。

因此不存在脱离工作负载的“永远最好”策略。策略优劣依赖：

- 查询/更新比 $\rho$；
- 新鲜度上限 $\Delta$；
- 带宽 $b$；
- 矩阵更新历史与溢出程度；
- OpenFHE 中实际的旋转、乘法、加密、解密和序列化成本；
- 多组件返回时的完整重构与掩码开销。

论文真正要回答的是：**如何先保证这些策略在语义上可比较，再在因果一致且成本完整的条件下寻找它们的 break-even 区域。**

# 与已有工作的边界：本文的新意只剩什么

这篇论文能否发表，很大程度上取决于是否把“已有原语”和“本文组合贡献”分清。最新一手来源审计给出的结论不是“没有人做过加密稀疏计算”，恰恰相反：相邻方向已经相当拥挤。因此，本文必须主动放弃宽泛的 `first` 叙事。

## 静态加密稀疏线性代数已经很丰富

- [CSSC](https://doi.org/10.1016/j.ins.2026.123180) 已经给出静态 `Value/ColumnIndex/RowMap`、行排序、压缩矩形、查询重排和聚合路径。本文继承的是它的静态 substrate，不把这些写成新贡献。
- [Lodia](https://eprint.iacr.org/2025/1425) 已经研究 batched FHE SpMV 的 low-diagonal decomposition；[Diagonal Packing / 2DPP](https://arxiv.org/abs/2604.04683) 已经研究用行列重排减少 occupied cyclic diagonals。因而“FHE-aware 稀疏布局或重排”不是本文首次。
- [CipherSkip](https://eprint.iacr.org/2026/297) 已经对任意形状 SpGEMM 加密 values 和 indices，并利用双方稀疏性；[SparseE](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108) 的 DAC 2026 官方摘要已经公开 encrypted-index Scatter--Gather--Apply 与 permutation/expansion accelerator。因而“首次隐藏 nonzero positions”“首次 encrypted indices”或“首次利用双边稀疏性”都不可主张。SparseE 尚无本次可核验的公开全文、DOI 和软件，不能据摘要反推其完整 leakage 或 update 语义。
- Ferguson et al. 的 [CPU ciphertext--ciphertext SpMSpM](https://doi.org/10.1145/3721146.3721948) 与 D'Agata et al. 的 [GPU/FIDESlib 扩展](https://doi.org/10.1145/3805621.3807642) 已经覆盖 CKKS 下的双边稀疏矩阵乘法。它们使用公开 sparse metadata、小型方阵和不同库/硬件，不能直接拿论文 wall-clock 与本项目 BFVRNS 动态 SpMV 数字比较，但足以排除宽泛的新颖性说法。

这里可守的差异不是一种新的静态 packing，而是：**当矩阵支持集随时间变化时，怎样维护 CSSC 组件，并保证每次查询使用同版本的列元数据、重构计划和返回绑定。** CipherSkip 所称的 server-side dynamic alignment 面向链式乘法中的加密中间结果，并不是 insert/delete/modify 驱动的 publication-state maintenance。

## 动态、版本和掩码也不是孤立的新原语

[d-DSE](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli) 说明动态加密数据库中的 update-volume leakage 不能仅靠一句“有 padding”带过，padding 本身还可能显著增加存储与通信成本。[CKKS-Auth Tree](https://doi.org/10.3390/electronics15122517) 已经使用 versioned root commitments 与 timestamps 检测更新后的 stale/replayed verification objects。因此，epoch、version、freshness check、replay rejection 或 padding 都不能单独当作本文创新。

[Rhombus](https://eprint.iacr.org/2024/1611) 已经在两方 MVM 中用随机减法把输出变成 additive shares，[Bonawitz et al.](https://doi.org/10.1145/3133956.3133982) 则提供了 canceling/zero-sum masks 的经典先例。本文不是发明零和掩码；候选贡献仅是让私有 `OutputPlan` 决定真实 overlap coordinates，并把每次 share 绑定到

$$
(q,v,d_{\Pi},k,b),
$$

也就是 query、version、plan digest、component 和 output block，再由持久 ledger 阻止同一 identity 被重复使用。

## 因而最终只能采用窄 gap statement

截至 2026-08-28 核验的一手材料中，没有找到同时覆盖下面四项的同任务方案：

1. insert/delete/modify 驱动的 FHE sparse-layout 增量维护；
2. 版本化、原子化的 publication state；
3. 与该版本绑定的全局列查询元数据；
4. RowMap-sensitive 多组件 SpMV 重构与 overlap-scoped 返回绑定。

这个检索结果只支持“我们研究一个尚未被这些近邻同时覆盖的窄交叉问题”，**不构成全球首次证明**。最终稿可以写 `we design an update-aware maintenance layer around static CSSC`；在没有公开系统检索协议、引用链和专利检索前，不能升级为 `the first` 或 `the only`。

实验上，唯一必须直接实现的外部 substrate counterfactual 是：在同一矩阵版本、参数、语料和成本边界下，每个 publication window 完整重建静态 CSSC。Lodia 只有在统一 OpenFHE 版本、BFVRNS 参数、矩阵形状、计费边界和 leakage contract 后，才可作为条件式静态 comparator；CipherSkip、SparseE、Ferguson、D'Agata、d-DSE、CKKS-Auth Tree 和 Rhombus 当前均是 citation-only，不能伪装成同任务动态 baseline。

# 系统与威胁模型

系统有三个角色：

- **Client A**：拥有矩阵、更新、CSSC 元数据、`ColumnIndex`、`RowMap` 和完整 `OutputPlan`，并生成 F1-M operands；
- **Client B**：拥有查询向量和 BFV secret key，接收完整私有 `OutputPlan`，解密并恢复最终逻辑结果；
- **Cloud**：执行 typed homomorphic DAG 的半诚实 evaluator。

冻结假设是

$$
\text{static semi-honest},
\qquad
\text{at most one corrupted party},
\qquad
\text{no Cloud/client collusion}.
$$

Cloud 可以观察 public parameters、密文 shape/count、公开 page/segment 形状、操作 schedule/timing、不透明 component/block ID、query/version ID 以及 plan/binding digest。Cloud 接口不得包含矩阵或更新明文、查询明文、secret key、全局 `ColumnIndex`、组件 `RowMap`、完整 `OutputPlan`、mask plaintext 或未掩蔽组件输出。

Client A 与 Client B 都被授权看到组件 `RowMap` 和完整重构计划；Client B 还明确接收全局列编号以构造查询。这里的“私有计划”始终表示**对 Cloud 私有**，不表示只对 Client B 可见。因此论文不能声称对任一 client 隐藏矩阵 support 或 reconstruction route。当前模型也不覆盖 malicious behavior、adaptive corruption、collusion、availability、side channel 或 traffic analysis。typed ACL 与 serializer 是可检查的接口约束，不是 simulation-based security proof。

# 核心设计一：版本绑定 Publication Window

## 版本化状态

对每个可见版本 $v$，定义完整发布状态

$$
S^{(v)}=
\left(
A^{(v)},
\mathcal{L}^{(v)},
M^{(v)},
\Pi^{(v)},
H^{(v)}
\right),
$$

其中：

- $A^{(v)}$：逻辑矩阵；
- $\mathcal{L}^{(v)}=\{L_1^{(v)},\ldots,L_K^{(v)}\}$：一个或多个物理 CSSC/base/delta 组件；
- $M^{(v)}$：该版本的全局列元数据与 `RowMap`；
- $\Pi^{(v)}$：私有输出重构计划 `OutputPlan`；
- $H^{(v)}$：对版本、计划和行为身份的规范化摘要。

状态能够发布的必要条件是物理解码严格还原逻辑矩阵：

$$
\operatorname{Decode}\!\left(\mathcal{L}^{(v)},M^{(v)}\right)=A^{(v)}.
$$

## 原子提交规则

设当前窗口积累的净更新为 $U_v$，则候选下一状态是

$$
\widetilde{A}^{(v+1)}=
\operatorname{Apply}\!\left(A^{(v)},U_v\right).
$$

维护策略生成候选物理状态

$$
\left(
\widetilde{\mathcal{L}}^{(v+1)},
\widetilde{M}^{(v+1)},
\widetilde{\Pi}^{(v+1)}
\right)
=
\operatorname{Maintain}\!\left(S^{(v)},U_v\right).
$$

只有当边界、类型、容量、版本和反解一致性全部通过时才允许提交：

$$
S^{(v+1)}=
\begin{cases}
\operatorname{Commit}(\widetilde{S}^{(v+1)}),
&\text{if }\operatorname{Validate}(\widetilde{S}^{(v+1)})=1,\\
S^{(v)},&\text{otherwise.}
\end{cases}
$$

因此失败转换不会让“新矩阵 + 旧 RowMap”或“新组件 + 旧查询计划”部分可见。

在正式评估中，`Validate=0` 不是“丢弃更新后继续跑”也不是“把同一批次悄悄挪到下一窗口”：该候选在该 cell 中被 fail-closed 记为 failed/infeasible，之后的状态和结果都不得进入选择或 headline；除预注册允许的整 shard 基础设施重跑外，不做选择性重试。

## Publication Window

Publication Window 是一个因果闭合区间，而不是普通批次。窗口 $W_v$ 内所有查询都读取同一个不可变版本：

$$
q\in W_v\quad\Longrightarrow\quad
\operatorname{version}(q)=v.
$$

窗口可以因查询到达、新鲜度截止、微批阈值或显式发布事件而关闭。实验中每个接受的原始事件组按固定顺序执行：

$$
\mathrm{SET}^{*}\rightarrow\mathrm{TICK}\rightarrow\mathrm{QUERY}^{*}.
$$

其中 `TICK` 即使在更新被裁剪为 no-op 时仍推进逻辑时间，防止 no-op 流量无限推迟新鲜度边界。窗口不能切开一个原子事件组。

# 核心设计二：版本化查询重排，而不是列号取模

论文冻结的发布域是

$$
m=4096,\qquad n=8193,
$$

而 BFV 有效的单行槽位域为

$$
s=4096.
$$

因为 $n>s$，全局列编号不能被错误地写成

$$
j\mapsto j\bmod s.
$$

该映射会让不同全局列发生别名，改变所计算的函数。

对版本 $v$ 的第 $k$ 个组件，设第 $p$ 个物理 lane 保存的全局列编号为 $g_{v,k,p}$。Client B 根据该版本的 `ColumnIndex` 构造对齐查询：

$$
\widetilde{x}_{v,k,p}=
\begin{cases}
x_{g_{v,k,p}},&g_{v,k,p}\text{ 是真实全局列},\\
0,&g_{v,k,p}\text{ 是 padding/tombstone/tail}.
\end{cases}
$$

随后对每个 lane 做同态乘法：

$$
z_{v,k,p}=\operatorname{Enc}(a_{v,k,p})
\odot
\operatorname{Enc}(\widetilde{x}_{v,k,p}).
$$

这里的关键贡献不是“有查询向量重排”——静态 CSSC 已经有这一思想——而是要求列元数据、对齐查询、组件、版本和最终重构计划形成一个不可替换的 typed bundle。

# 核心设计三：OutputPlan 统一重叠、拼接和隐式零

## 为什么不能把所有返回密文直接相加

维护后的矩阵可能由多个 Result Component 组成。不同返回值可能有三种关系：

1. 对同一个逻辑坐标提供多个贡献，需要模加；
2. 对互不相交的逻辑坐标提供贡献，需要重排后拼接；
3. 某个逻辑坐标没有物理贡献，应保持为隐式零。

如果只看“返回了几个密文”，无法区分这三种情况。

## 映射与贡献集合

`OutputPlan` 定义私有映射

$$
\Pi_v:(k,b,p)\longmapsto i\ \text{或}\ \bot,
$$

其中 $k$ 是组件，$b$ 是 Output Block，$p$ 是物理 lane，$i$ 是最终逻辑输出坐标，$\bot$ 表示该 lane 不贡献结果。

对逻辑坐标 $i$，定义贡献集合

$$
\Gamma_i^{(v)}=
\left\{(k,b,p):\Pi_v(k,b,p)=i\right\},
$$

以及 contributor multiplicity

$$
h_i^{(v)}=\left|\Gamma_i^{(v)}\right|.
$$

Client B 先把最终结果初始化为零，再按计划恢复：

$$
y_i^{(v)}=
\begin{cases}
0,&h_i^{(v)}=0,\\
\operatorname{Center}_t(z_s),&h_i^{(v)}=1,\\
\operatorname{Center}_t\!\left(\displaystyle\sum_{s\in\Gamma_i^{(v)}}z_s\bmod t\right),&h_i^{(v)}>1.
\end{cases}
$$

这样，水平不相交的 block 不会被误加，重叠坐标也不会被误拼接。

## 公开摘要与私有计划

完整 `OutputPlan` 含 `RowMap` 敏感信息，由 Client A 生成并持有，再交给 Client B 用于重构；它不交给 Cloud。Cloud 只获得规范化摘要

$$
d_v=\text{SHA-256}
\left(\operatorname{CanonicalJSON}(\Pi_v)\right).
$$

$d_v$ 是绑定标识，不是让 Cloud 获得计划原文的授权。每个执行请求、返回 share 和掩码都携带同一个 $d_v$，从而拒绝跨版本或跨计划拼接。

这里的 SHA-256 只提供规范化内容绑定，不提供密码学 hiding。若计划空间低熵或可枚举，Cloud 可能离线猜测摘要，也能观察相同摘要的链接关系；因此准确主张只能是“接口不直接交付完整计划”，不能把 $d_v$ 本身写成隐藏性证明。需要隐藏型绑定的部署应改用独立冻结的带密钥或带随机盐方案，而不能事后替换当前协议。

关键绑定字段的作用域如下：

- $v$ 由发布状态产生，在一个 Publication Window 内唯一并由三方核对；
- $q$ 由查询生命周期产生，对一次查询唯一；
- $d_v$ 由规范化 `OutputPlan` 计算，是 Cloud 可见的计划绑定标识；
- `component` 与 `output block` 是 Cloud 可见的不透明物理路由 ID；
- $\beta=(q,v,d_v,\mathrm{component},\mathrm{output\ block})$ 是 Client A 持久化 ledger 的一次性键，执行前由 Client A 保留，Cloud 只核对随密文携带的绑定，Client B 按完整计划恢复。

# 核心设计四：只对真实重叠做 F1-M 零和掩码

## 目标

当一个逻辑坐标由多个组件贡献时，如果 Client B 分别解密每个组件，它会看到本不需要暴露的组件级中间值。F1-M 的目标是让 Client B 能恢复总和，但不能直接得到未掩蔽的各组件贡献。

这不是新的零和掩码原语；论文的贡献是把它精确地接到版本化 CSSC 的 `OutputPlan` 上，并把“一次性”要求变成持久化、可失败关闭的绑定。

## 零和构造

若某个逻辑坐标的 multiplicity 为 $h>1$，Client A 在 $\mathbb{Z}_t$ 上采样

$$
r_1,\ldots,r_{h-1}\overset{\$}{\leftarrow}\mathbb{Z}_t,
$$

并令

$$
r_h=-\sum_{j=1}^{h-1}r_j\pmod t.
$$

于是

$$
\sum_{j=1}^{h}r_j=0\pmod t.
$$

Cloud 返回掩蔽后的 share

$$
\widehat{z}_j=z_j+r_j\pmod t.
$$

Client B 合并时得到

$$
\sum_{j=1}^{h}\widehat{z}_j
=
\sum_{j=1}^{h}z_j+\sum_{j=1}^{h}r_j
\equiv
\sum_{j=1}^{h}z_j
\pmod t.
$$

上述代数在协议中的消息流是明确的：Client A 同时持有组件 `RowMap` 和完整 `OutputPlan`，先按 $\Gamma_i^{(v)}$ 在逻辑坐标上生成零和值，再把每个值映射到对应 `(component, output block, lane)` 的物理向量；随后使用 Client B 的 BFV public key 加密该向量，并把绑定后的掩码密文交给 Cloud。Cloud 只执行“结果密文 + 掩码密文”，不需要也不得获得 $\Gamma_i^{(v)}$ 或 mask plaintext。Client B 解密各个已掩蔽 share，按私有 `OutputPlan` 重排并在 $\mathbb{Z}_t$ 中合并，最后只做一次 centered lift。

$\Gamma_i^{(v)}$ 是逻辑坐标粒度，而 $\beta$ 是 Output Share 粒度：同一 `(component, output block)` 可以有多个 lane 落到一个或多个 $\Gamma_i^{(v)}$ 中，这些 lane 的掩码值装在同一个物理向量 tuple 里；ledger 对整个 share 只保留一次 $\beta$，不会为每个 lane 伪造新的查询身份。

因此这里能给出的只是冻结 ACL 与单次半诚实、无串通模型下的设计级泄漏边界：Cloud 看到形状、数量、schedule、不透明路由 ID 和绑定摘要；Client B 看到完整重构路线和最终和。它不是 simulation-based security proof，端到端加密执行仍必须由 R4 门禁证明，当前文字不得把代数抵消等式写成已经完成的安全证明。

## 为什么 multiplicity 为 0 或 1 时不应随机掩码

若 $h=0$，结果就是隐式零，不应该制造一个虚假的返回密文。

若 $h=1$，不存在需要隐藏的组件间分解；该 share 只需重排或拼接。为它强行增加随机掩码既没有零和伙伴，也会虚增加密、通信和客户端工作。因此规则是：

$$
h_i\le 1\quad\Longrightarrow\quad\text{不生成随机零和掩码}.
$$

强路径为了保持公开操作位置一致，可以加入**加密零 dummy**。它和随机零和掩码是两个不同的成本类别，不能混算。

## reserve-before-sample

每个掩码绑定到五元组

$$
\beta=
(q,\ v,\ d_v,\ \text{component},\ \text{output block}).
$$

持久化 SQLite ledger 在采样前原子保留该绑定：

$$
\operatorname{Reserve}(\beta)
\prec
\operatorname{SampleMask}(\beta).
$$

重复绑定被拒绝；进程在保留后崩溃时，该绑定仍按已消耗处理。这样避免“先采样、后记录”在崩溃窗口中导致同一身份重新取掩码。

该保证只覆盖冻结的 ledger 模型。仓库回滚、数据库复制、跨设备协调或数据库被攻破不在当前安全主张内。

# 核心设计五：固定分段 strong delta

## 设计动机

普通增量可以把少量变化放入客户端处理的 Packed-COO lane，但那条路径是非选择性 ablation。论文指定的 strong reference 把 overflow 放入 Cloud 可执行的固定宽度分段，同时把同一逻辑行的最终合并关系留在 Client B 的私有计划中。

强路径写成

$$
A^{(v)}=A_{\mathrm{base}}^{(v)}+A_{\mathrm{seg}}^{(v)}.
$$

其中 $A_{\mathrm{base}}^{(v)}$ 是真实 CSSC base，$A_{\mathrm{seg}}^{(v)}$ 由固定宽度段组成。

## 固定宽度与页面

协议固定

$$
c=128=2^7.
$$

每个 segment 只包含一个逻辑行的条目。4096 个有效槽位可容纳

$$
\frac{4096}{128}=32
$$

个完整 segment；段内 reduction 深度为

$$
\log_2 128=7.
$$

$c=128$ 是预先冻结的协议身份，而不是从真实语料结果中调出来的最优值。论文只能报告这个点，不能外推“128 对所有矩阵都最优”。

## Cloud 侧固定 reduction

对一个 segment 的 lane-wise 乘积向量 $u^{(0)}$，固定旋转—相加图可以抽象为

$$
u^{(r+1)}=u^{(r)}+
\operatorname{Rot}\!\left(u^{(r)},2^r\right),
\qquad r=0,\ldots,6.
$$

为避免旋转方向歧义，冻结 lane 编号为 $0,\ldots,4095$，每个 segment 的 leader 是起点 $a\in\{0,128,\ldots,3968\}$，并采用与可执行 OpenFHE witness 一致的约定

$$
\left[\operatorname{Rot}(u,s)\right]_{\ell}
=u_{(\ell+s)\bmod 4096}.
$$

在第 $r$ 轮完成后，leader lane 保持不变量

$$
u_a^{(r)}=
\sum_{j=0}^{2^r-1}u_{a+j}^{(0)},
\qquad r=0,\ldots,7.
$$

因为 $a$ 是 128 的倍数且最大 shift 为 64，leader 的读取区间始终停留在自己的 128-lane segment 内；其他 lane 即使含跨段中间量，也会在下一步被公开的 segment-start mask 丢弃。

随后用公开的 segment-start mask 只保留 leader：

$$
\ell=\operatorname{Mask}_{\mathrm{leader}}\!\left(u^{(7)}\right).
$$

Cloud 可以执行统一页面调度，但不知道多个 leader 是否属于同一逻辑行。Client B 根据私有 `OutputPlan` 把同一逻辑坐标的 leader 合并。

每个可见返回位置都执行一次 F1-M operand addition：真实重叠使用随机零和掩码，不相交返回使用加密零 dummy。由此既保持执行图的类型稳定，又把两类对象分别计费。

# 三个固定策略：不是在线万能选择器

Route A 不再从十四个候选中训练或挑选 winner，也没有 tuning-selected policy 或 held-out oracle。正式结果只比较三个在 Stage 1 已冻结身份和状态转移语义的策略：

1. **PeriodicRepack**：`periodic-repack/windows=1`，每个 Publication Window 都从完整逻辑矩阵重新构造并发布静态 CSSC，是最干净但更新开销最高的基线；
2. **PaddingReuse-CSSC**：`padding-reuse`，先复用最低序号 tombstone，再复用自然 padding；若都不可用，就重建受影响的固定水平行分区；
3. **Packed-COO-Cloud-Segmented-Delta**：`packed-coo-cloud-segmented-delta/segment-width=128`，base 仍是 CSSC，溢出被放进 Cloud 可执行的固定 128-lane 行拥有分段，永不在线折叠。

三者消费完全相同的有序事件、Publication Window、查询到达、初始矩阵和公开参数。论文不把任何一个策略写成全局最优，也不允许根据 held-out 结果切换策略。真正的问题是：在两个冻结规模、四个合成查询/更新比、一个真实来源的两种事件语义，以及六个当前源码 OpenFHE case 中，三个固定机制分别付出什么代价。

# 成本与测量口径

## 五类证据必须分开

对策略 $k$、规模 $s$ 和查询/更新比 $\rho$，结果不是一个混合总分，而是带类型标签的成本向量：

$$
\mathbf{c}_{k,s,\rho}
=
\left(
T_{\mathrm{state}},
T_{\mathrm{assembly}},
N_{\mathrm{op}},
B_{\mathrm{meta}},
\overline{B}_{\mathrm{crypto}},
\mathrm{RSS}_{\max},
\mathrm{scratch}_{\max}
\right).
$$

其中：

- **直接测量**：合成与 SNAP 直接执行 cell 的状态转移时间、结果装配时间、独立 replay 时间、峰值 RSS 和受控 scratch；
- **精确计数**：事件、窗口、更新、查询、typed primitive 和对象 multiplicity；
- **上界投影**：合成与 SNAP 的密码对象字节，由精确对象 multiplicity 乘以 S1 冻结的类型级最大序列化公式得到；
- **精确缩放**：只允许把 $\rho=1$ 的注册查询线性计数和字节字段变换为 $\rho=10$；
- **原生实测**：六个 OpenFHE case 的真实 typed-operation inventory、序列化对象字节、进程时间、RSS 和 scratch。

这些类别不会折成一个来源不明的“估计性能”。特别是 simulator 的 primitive count 不是 OpenFHE 延迟，replay 时间是证据开销而不是策略运行成本，native package 的真实字节也不能事后替换 S1 冻结的合成/SNAP 字节上界。

对允许缩放的查询线性字段，变换严格是

$$
n^{(10)}_{q,p}=10\,n^{(1)}_{q,p},
\qquad
n^{(10)}_{u,p}=n^{(1)}_{u,p}.
$$

$\rho=10$ 不产生 wall time、RSS、scratch 或原生延迟；这些量在结果表中必须标为 unavailable，而不是从 $\rho=1$ 外推。

## 通信字节与带宽换算

设一个接受的事件组引起的规范更新侧字节为 $B_u$，一次查询引起的查询侧字节为 $B_q$。在带宽 $b$ Mbps 下，单纯的协议字节换算为

$$
T_{\mathrm{net}}(B,b)
=
\frac{8B}{b\times 10^6}.
$$

合成与 SNAP 的密码对象上界按类别 $j$ 计算：

$$
\overline{B}_{\mathrm{crypto}}
=
\sum_j m_j U_j,
$$

其中 $m_j$ 是精确对象 multiplicity，$U_j$ 是 S1 冻结的类型级最大字节数。实际规范元数据字节单独报告；HTTP/TLS、GitHub artifact wrapper、文件系统和 replay 私有证据传输也分别记账，不能伪装成协议 Cloud 通信。

## OpenFHE 原生 case 不与 simulator 混加

当前源码 OpenFHE 矩阵只有三个策略乘两个规模，共六个 case。每个 case 都执行

$$
1\ \text{discarded warm-up}
+3\ \text{fresh-key producer evaluations}
+3\ \text{exact package replays}.
$$

所以完整原生工作量是

$$
6\times(1+3+3)=42
$$

次 native evaluation。三个 producer 是同一固定 case 的技术重复，不是独立总体样本。论文报告三个原始值、其中位数和范围：

$$
\widetilde{T}^{\mathrm{native}}_{k,s}
=
\operatorname{median}
\left(
T^{(0)}_{k,s},
T^{(1)}_{k,s},
T^{(2)}_{k,s}
\right),
$$

并分别报告 producer 与 replay。q4 必须反序列化 q3 留下的 CryptoContext、密钥、evaluation-key frame 和输入密文；它的 lifecycle inventory 要求 context/key/evaluation-key generation 与 Encrypt 全为零，但 Cloud-program operation inventory 必须与同一 package 的 producer 完全相同。

# 三类正式实验矩阵

## 合成矩阵：两个规模、三个种子、四个 rho

合成矩阵冻结为：

- **S**：256 行、8,193 列、512 个 accepted updates；
- **M**：1,024 行、8,193 列、2,048 个 accepted updates；
- formal seeds：$\{20260822,20260823,20260824\}$；
- workload：`mixed-insert-delete-modify`；
- $\rho\in\{0.01,0.1,1,10\}$；
- 每个 cell 同时执行三个固定策略。

因此 formal synthetic unit 数量是

$$
2\ \text{scales}\times3\ \text{seeds}=6\ \text{shards}.
$$

对于最简分数 $\rho=p/q$ 和从零开始的 accepted-event ordinal $a$，第 $a$ 个完整事件组之后插入的查询数是

$$
Q_a
=
\left\lfloor\frac{(a+1)p}{q}\right\rfloor
-
\left\lfloor\frac{ap}{q}\right\rfloor,
$$

于是前 $N$ 个事件组后的查询总数严格为

$$
\sum_{a=0}^{N-1}Q_a
=
\left\lfloor\frac{Np}{q}\right\rfloor.
$$

$\rho\in\{0.01,0.1,1\}$ 完整执行；$\rho=10$ 只能从同策略、同 shard 的 $\rho=1$ 结果做注册的 query-linearity 变换。任何 event/window/state 不等价、任何试图缩放非白名单字段，都会让该 shard fail closed。

## 单一真实来源：SNAP Stack Overflow A2Q

真实来源只使用一个固定对象：SNAP Stack Overflow `sx-stackoverflow-a2q.txt.gz`。acquisition 先记录最终 URL、响应头、精确压缩字节数与 SHA-256；独立 guard 再下载一次，要求 exact response-body bytes 相同，正式工件不携带原始压缩对象。

确定性 transform 使用：

- 前 1,000,000 条 eligible records 冻结 row/column mapping；
- 两个按 source identity 哈希得到的确定性分区；
- 每个分区 1,024 行、8,193 列；
- mapping prefix 之后每个分区 4,096 个 accepted records；
- 两种事件语义 T1 与 T2；
- $\rho\in\{0.1,1\}$；
- 三个固定策略。

因此 ordered-event formal matrix 是

$$
2\ \text{partitions}\times2\ \text{semantics}=4\ \text{shards}.
$$

T1 是累计 occurrence：

$$
A_{uv}(t)=\min\{7,N_{uv}(t)\}.
$$

T2 保留最近 $K=1024$ 个 accepted events，窗口满时先 expiry、后 admission；这两个 SET 属于同一个不可拆分的 atomic group。查询时钟是每 128 个 accepted records 一秒的合成逻辑时间，因此该矩阵只支持“同一来源上的有序事件交互”结论，不支持多来源或历史 wall-clock 稳健性外推。

## 当前源码 OpenFHE 矩阵

原生矩阵只运行

$$
3\ \text{strategies}\times2\ \text{scales}=6\ \text{cases}.
$$

所有 case 使用 seed $20260822$、$\rho=1$、终端 accepted-event prefix（S 为 512，M 为 2,048）以及最后一个事件组之后的查询。每个 case 固定同一 version、component inventory、query vector、`OutputPlan`、typed execution plan 和完整规范输入字节；不得改用更早或更方便的快照。

每个 producer 只上传一个一天保留、永久 NON-EVIDENCE 的 handoff；独立 replay 下载并重哈希，guard 才能产生一个 formal shard artifact。warm-up 不保留可 replay package，只有 recorded ordinals 0、1、2 被重放。

## 完整工件数量

正式 campaign 只有以下可接纳对象：

$$
1\ \text{acquisition}
+6\ \text{synthetic}
+4\ \text{ordered-event}
+6\ \text{OpenFHE}
=17\ \text{pre-aggregate artifacts}.
$$

terminal admission 必须独立重哈希并一次性接纳恰好这 17 个对象，随后才允许生成一个 aggregate 和一个 compatible detached S3 analysis bundle。缺少、额外、重复、错误 attempt 或错误 kind 都拒绝。

# 因果解释、报告规则与否证条件

这里的“因果”只表示配对反事实：在同一个冻结事件流、初始状态、查询调度和公开参数下，只替换维护策略。对策略 $a,b$ 的配对差可写为

$$
\tau_{a,b}(u,\rho)
=
C_a(E_u,\rho)-C_b(E_u,\rho),
$$

但 $C$ 必须保持为预注册测量字段或成本向量，不允许把 native latency、simulator counts、上界字节和 replay overhead 混成一个没有来源标签的标量。

S/M 只有两个规模，连接线只是视觉辅助；两个真实分区和三个 native producer 也都不是总体随机样本。因此论文报告所有 raw points、median/range 和机制级分解，不拟合 scaling exponent，不给总体 $p$ 值或置信区间，不宣称 global winner、Pareto frontier 或隐私等价。

Route A 会被以下任一事实否证并转为 Route C：

- 合法 ordinary/strong 输出与 typed 或 direct plaintext oracle 不一致；
- 非法 version/query/plan/payload 替换被接受；
- F1-M identity 能复用，或随机掩码不能严格模 $t$ 抵消；
- 当前源码 OpenFHE ordinary/strong case 不能在普通 runner 完成；
- qualification、任一 formal critical path 或 12 小时 campaign 门槛失败；
- 必须增加第二套 adapter、receipt 或 evidence hierarchy 才能跑完；
- 三个策略在所有 ordered-event cell 产生完全相同的有序状态演化和成本向量；
- bounded primary-source novelty gate 失效或发现已有工作覆盖完整四条件组合。

某个策略更慢、没有占优或只在部分 $\rho$ 有利，并不构成失败；它会作为边界或负结果如实报告。

# 证据链为什么被设计得很严格

## 三类源快照

项目区分：

- Experiment Source Snapshot：真正执行实验的提交；
- Evidence-Freeze Snapshot：只安装已生成工件的 data-only anchor；
- Analysis Source Snapshot：执行最终验证器和分析器的提交。

三者不要求 SHA 完全相同，但差异必须由仓库拥有的 Behavior Set 和 compatibility receipt 证明只发生在允许的证据路径。普通 ancestor 关系、producer 自报文件清单或一个布尔 `verified=true` 都不够。

## Route A 的 S1 与 S2 已冻结，资格已选择 Route C

旧 Day 1A lineage 的 S1/S2 没有被继承为 Route A 的实验权威。Route A 已从不含旧诊断 anchor 的新 ancestry 完成：

1. 在 runner 实现前共同冻结 preregistration、machine plan、bounded novelty review 与 claim ledger；
2. 完成全部 runner、workflow、schema、Behavior Set、compatibility verifier、guard、proof、source-conformance record 和 analyzer；
3. 对 exact behavior-source diff 做材料门审查并通过 exact-head Linux CI，才可指定干净的 Experiment Source Snapshot S1；
4. 只从 exact S1 生成描述性 registration archive 并由第二进程复核；
5. 只增加该 registration data anchor，形成 terminal Evidence-Freeze Snapshot S2；
6. 由仓库拥有的 ADR 0010 verifier 证明 S1 到 S2 的 closed Behavior Set 在 path、type、mode 和 Git blob 上完全相等，且不存在额外行为文件。

最终 S1 是 `ee58627bb5752c6ac1ee2c5132c6574f9cb66552`，其 tree 与双专家审过的 `baefc8cc…` 完全相同；最终 S2 是只增加 registration anchor 的 `c7ff6820d9323f1850c1c5c57fd9070db88db120`。compatibility receipt 证明 S1 到 S2 的封闭 Behavior Set 未漂移。父系和早期候选的成功 CI/PRE-S1 只保留为工程历史，没有被冒充成当前身份的证据。

workflow 控制面从 exact S2 dispatch，并从 fresh detached exact-S1 checkout 执行 qualification computation。该身份分离已经在唯一 qualification 中兑现；但资格没有产生 GO，所以 acquisition 与 formal producer/replay/guard 均被永久禁止在本次预注册下启动。

## 四个执行层级

1. **NON-ADMISSIBLE qualification**：q1 synthetic producer、q2 independent replay/guard、q3 case-shaped native producer、q4 exact native replay/guard、q5 combined guard、q6 postrun resource admission。它最多产生六个一天保留的非证据 artifact，永远不进入论文结果；
2. **Acquisition/transform**：两次独立下载锁定同一 SNAP response-body bytes，输出一个不含原始压缩对象的 guarded formal acquisition artifact；
3. **Formal campaign**：严格串行执行 6 synthetic、4 ordered-event 和 6 OpenFHE shards，每个都遵循 producer → one-day NON-EVIDENCE handoff → independent replay → guard → formal artifact；
4. **Terminal/aggregate/S3**：terminal admission 接纳恰好 17 个 pre-aggregate artifacts，随后产生一个 aggregate，并仅在 exact-compatible detached S3 上运行冻结 analyzer。

因此必须保持三条边界：**测试通过不推出已经有论文性能结果；workflow 成功不推出 artifact 可采信；artifact 可重放也不推出 qualification、terminal admission 或论文主张已经释放。**

# 正确性边界与整数安全

冻结参数包括 BFVRNS、ring dimension 8192、plaintext modulus

$$
t=65537,
$$

单行最多 4096 个非零项，且

$$
|A_{ij}|\le7,
\qquad
|x_j|\le1.
$$

所以单个逻辑输出的绝对值上界为

$$
M_{\max}=4096\times7\times1=28672.
$$

由于

$$
2M_{\max}=57344<t=65537,
$$

最终组件和在模 $t$ 中具有唯一 centered lift。必须先在 $\mathbb{Z}_t$ 中合并全部组件，再做一次 centered lifting；不能对每个组件先 centered lift 再相加。

这个上限在正式路径中不是纸面假设：synthetic/SNAP producer 逐事件维护 `peak_row_nonzeros`，独立 replay 重算峰值；策略状态转换在发布前再次拒绝超过 `max_row_nnz` 的候选逻辑状态。任何超限 unit 都会 fail closed，而不会带着失效的 centered-lift 前提进入 Route A formal artifact。

这只证明冻结整数边界下不存在模回绕歧义，不等价于 mixed-circuit 噪声预算安全。后者需要独立 OpenFHE 门禁。

# 论文真正可以声称什么

## 可以主张的贡献

1. 围绕静态 CSSC 的版本绑定可变维护语义；
2. 显式区分重叠求和、水平拼接和隐式零的私有 `OutputPlan`；
3. `OutputPlan` 驱动、只覆盖真实重叠且带持久 no-reuse identity 的 F1-M 集成；
4. 固定 $c=128$ strong delta 的 typed whole-query execution path；
5. 把三个固定策略的独立持久状态、typed cost provenance、完整序列化记账和 commit-bound evidence 组合成 fail-closed 评估方法。

## 不能扩大成的主张

- 不是新的 BFV/FHE primitive；
- 不是第一个稀疏同态矩阵—向量乘法；
- 不是新的静态 CSSC；
- 不是首次 encrypted indices、隐藏 nonzero positions、双边稀疏 FHE 计算、版本承诺或随机输出 sharing；
- 不声称 formal security、malicious security、collusion security 或全侧信道保护；
- 不声称 $c=128$ 全局最优；
- 不声称在所有矩阵、数据集或 $\rho$ 上优于重压缩；
- 不把合成 simulator 计数当作真实语料或 OpenFHE 原生性能；
- 不把 deterministic partitions 当作总体随机样本；
- 不在真实结果不满足规则时重新调参或删掉失败 unit。

如果完整机制或证据门禁不通过，预注册允许的 fallback 是 benchmark/methodology、边界刻画或负结果论文；不允许的 fallback 是看完正式结果后修改矩阵、门槛或策略身份并继续声称原结论。

# 这篇论文的叙事主线

一篇清晰的最终论文可以按以下逻辑展开：

1. **静态格式的缺口**：CSSC 对静态稀疏模式有效，但更新会同时改变数据、列重排和结果映射；
2. **系统不变量**：提出 Publication Window 与原子版本提交，保证矩阵、布局、查询和重构同版本；
3. **多组件语义**：用 `OutputPlan` 明确重叠、拼接和隐式零；
4. **隐私化返回**：只对真实重叠应用一次性零和掩码，并持久绑定 no-reuse identity；
5. **可执行增量路径**：固定分段 strong delta 把统一 schedule 留给 Cloud，把逻辑行合并留给 Client B；
6. **策略不是免费午餐**：增量减少更新成本，却可能增加查询成本；
7. **用同一冻结合同找边界**：synthetic matrix 暴露因果计数和状态转换成本，current-source OpenFHE matrix 给出真实密码执行与完整序列化成本，ordered-event matrix 检验真实来源顺序下的配对表现；
8. **结果无论正负都可解释**：报告三个固定策略在冻结规模、$\rho$ 和事件语义下的机制级权衡；若增量维护失去优势，就把失效位置与原因写成边界或负结果。

# 当前进度与剩余工作

以下状态以 2026 年 8 月 30 日的精确仓库与 GitHub 记录为准。这里必须区分“方法已经实现”“工程门禁已经通过”“一次性资格是否通过”和“论文经验结果是否产生”四件事；任何前一层都不能替代后一层。

已经完成或建立的主要内容包括：

- typed state、Publication Window、query compiler、`OutputPlan`、F1-M persistent ledger、strong fixed-segment path、plaintext oracle、独立 replay、完整序列化计数和 fail-closed artifact validator；
- Route A methods-first manuscript、预注册、claim ledger、bounded primary-source novelty matrix，以及 S1（实验行为）、S2（只增加终端注册数据）、S3（兼容分析）三快照分离；
- 旧 Day 1A 路线的两次可审计 NO-GO。run `33099397289` 在 300 分钟时 replay 尚未完成；修复后的 run `33130154591` 仍在 producer 291.92 分钟后只剩约 8 分钟，replay 仅完成 $\rho=0.01$ 单元便触及止损，guard 被跳过。两次都按原门槛取消，没有被包装为成功，也没有再授权第三次诊断；
- 最终行为候选 `baefc8cc…` 的 Pro/ZCode 双 PASS、PR #39、S1 `ee58627…`、S2 `c7ff682…`、S1/S2 exact-head CI、两次 non-authorizing PRE-S1、描述性 registration 与 compatibility receipt 均已闭合；
- Route A 的一次性资格 q1--q6 已真实启动且按冻结规则终止。run `33261434612` 中 q1 成功，q2 在 replay 中被取消，q3--q6 未执行；45 分钟门槛到达时 q5 未成功，因此裁决为 Route C。唯一 artifact 是 621,877,534-byte 的 `q1-simulator-pre-replay-handoff`，保留一天、永久 NON-ADMISSIBLE；没有 formal artifact 或 dispatch capability；
- controller 的止损动作正确且只作用于 exact run。取消后的 GitHub API 为两个空下游 jobs 返回了反常终态时间戳，导致最后一次读取 fail-closed；这是一项需要在未来新 lineage 中修复的 provider-boundary 兼容问题，但没有造成假接受，也不能成为本次重跑资格的理由；
- q3/q4 的 retained build/package 绑定、zero-KeyGen/zero-Encrypt replay、跨 lane 不同 request/query/preparation/key identity，以及“producer 与 replay 只在同一 package 内相等”的反欺骗约束；
- q5 对 provider artifact id/name/digest/size/head/run 的二次校验、安全 ZIP 解包、probe 与六个 formal structural vectors 的重算。operation counts 和 type-derived maximum bytes 只是一项必要 planning screen，明确不是 wall-time theorem；

本次 Route A 的工程执行已经完成，但**正式经验结果仍为零**。这不是“再等几个小时实验就会出来”：预注册明确禁止重跑 qualification，也禁止在没有 GO capability 时启动 acquisition、6 个 synthetic shards、4 个 ordered-event shards、6 个 OpenFHE cases、terminal aggregate 或 S3 accepted analysis。因而原来的正向结果稿路线在本次 lineage 内已经关闭。

接下来的关键路径改为 Route C：

1. 冻结资格 NO-GO 的 provider 元数据、唯一 non-evidence artifact 元数据、controller cancel 记录和终态异常说明，形成可核验但不冒充 formal performance evidence 的 provenance；
2. 把英文 manuscript 从“等待结果的 skeleton”改成“version-bound protocol + functional propositions + fail-closed evaluation boundary”的 methods/boundary paper，删除会让读者期待正式策略胜负的占位句；
3. 只把 S1/S2 CI、PRE-S1、registration、source-conformance、proof obligations 和资格裁决放进各自允许的证据层；不把 q1/q2 片段用于 strategy-cost、speedup 或 OpenFHE 性能结论；
4. 补齐协议图、版本/查询/重构图、correctness/fail-closed matrix、证据边界表和资格 DAG/停止点时间线；不生成伪造的性能曲线；
5. 让 ChatGPT Pro 与 ZCode 对 Route C 完整稿做同包反审，清掉 P0/P1，再生成带可编辑公式的 Word/PDF 和投稿附件；
6. 由作者选择适合 methods/protocol、negative result 或 reproducibility 的 workshop/short-paper 目标，并补 funding、CRediT、利益冲突和最终 AI disclosure。

按当前已完成程度，**工程/审计链约为 95%--100%**，但原定正向经验结果链为 **0% 且已关闭**；以 Route C 可投稿稿为新目标，整体约为 **65%--75%**。在不新增实验 lineage 的前提下，形成一版结构完整、可供专家逐段审稿的 Route C 稿预计还需 **5--10 个日历日**；完成图表、引用核验、双专家终审、Word/PDF 视觉检查和投稿材料，较可信的窗口是 **2--4 周**。如果坚持必须得到正向策略性能结果，则需要新的研究问题、预算和预注册 lineage；这不是本次任务的“续跑”，保守看至少另需 **3--6 周**，而且仍不保证结果为正。以上是形成投稿稿的估计，不是录用时间承诺。

# 最终理解

这篇论文最重要的 idea 可以压缩成下面这个等式：

$$
\boxed{
\text{Mutable encrypted SpMV}
=
\text{versioned state}
+
\text{versioned query}
+
\text{private reconstruction}
+
\text{complete causal cost}
}
$$

它研究的不是“某个 delta 数据结构是否快”，而是：在一个会更新的加密稀疏矩阵系统里，怎样保证每个查询算的是正确版本、每个返回值按正确逻辑坐标恢复、每个隐私化中间值只被正确使用一次，并且最终的性能比较没有偷掉更新、通信、返回密文、客户端重排或候选历史。

如果这些不变量闭合，论文就能可信地回答增量维护的适用边界；如果真实实验不通过，它也能可信地说明边界在哪里。这种“结果可以为正，也可以为负，但证据链不能含糊”的方法论，正是本项目区别于普通原型 benchmark 的核心。

# 项目内主要依据

- `docs/paper/manuscript-draft.md`
- `docs/paper/publication-preregistration-route-a.md`
- `docs/paper/claim-ledger-draft.md`
- `config/route-a-publication-plan.json`
- `config/route-a-behavior-sets.json`
- `docs/research/route-a-complete-combination-novelty-review-2026-08-28.md`
- `docs/reviews/route-a-native-q3q4-material-gate-2026-08-29.md`
- `docs/protocol-patch-v2.1b.md`
- `docs/decisions/0003-f1m-hidden-rowmap.md`
- `docs/decisions/0005-output-plan-overlap-blinding.md`
- `docs/decisions/0006-persistent-strategy-snapshots.md`
- `docs/decisions/0007-anonymous-fixed-segment-primitive.md`
- `docs/decisions/0008-strong-whole-query-execution-bundle.md`
- `docs/decisions/0010-separate-experiment-and-evidence-freeze-snapshots.md`
- `docs/decisions/0012-window-weighted-day1b-accounting.md`
- `config/params_manifest.json`

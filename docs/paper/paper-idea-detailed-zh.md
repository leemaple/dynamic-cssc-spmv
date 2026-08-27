---
title: "Dynamic CSSC SpMV：论文核心 Idea 与完整技术路线"
subtitle: "面向可变稀疏矩阵同态矩阵—向量乘法的版本绑定维护、私有重构与可审计评估"
author: "项目技术说明（methods-first；实验结论尚未解封）"
date: "2026-08-27"
lang: zh-CN
numbersections: true
---

# 阅读提示

本文解释这篇论文“到底想解决什么、核心 idea 是什么、为什么需要这些机制、公式如何连接到实现，以及最后怎样用实验回答问题”。它不是结果论文的替代稿，也不把尚未完成的实验写成结论。

截至 2026-08-27，项目已经完成大部分协议、实现、验证器、工作流和论文方法框架。当前 Day 1A registration 的实验源 S1 为 `b658e2178b210c2cc0012fc61957a3b3a92953bb`，唯一 data-only Terminal Registration Freeze S2 为 `bb83d4e42209e24df0c71df3eea5df7cbff7e1d5`；S2 的 exact-head CI 已通过。唯一的 NON-ADMISSIBLE 单分片性能诊断 run `33075408647` 已启动但尚未完成，因而仍没有可写入论文的 Day 1A 经验结果。正式 Day 1A、Day 2、真实语料 Day 1B、mixed-circuit 和 R4 结果尚未全部产生或接纳。因此，本文中的“设计”“机制”“计划验证”与“已经得到的经验结果”会严格分开。

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

# 核心设计一：Publication Window 与版本绑定提交

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

# 核心设计三：`OutputPlan` 统一重叠、拼接和隐式零

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

# 候选策略与“不是在线万能选择器”

论文比较的是冻结的固定维护策略，不是边跑 held-out、边选择最优策略的在线 oracle。

候选族主要包括：

- `padding-reuse`；
- `mini-cssc-delta`；
- `strict-local-repack`；
- `reserved-slack/beta=0`；
- `reserved-slack/beta=0.05`；
- `reserved-slack/beta=0.1`；
- `reserved-slack/beta=0.2`；
- `reserved-slack/beta=0.4`；
- `periodic-repack/windows=1`，即每窗口全量重压缩，是主比较基线；
- `periodic-repack/windows=4`；
- `periodic-repack/windows=16`；
- `periodic-repack/windows=64`；
- `packed-coo-cloud-segmented-delta/segment-width=128`；
- `packed-coo-client-lane-delta/capacity=128`，仅作为 ablation，不得参与选择。

完整角色合同是

$$
14\ \text{fixed records}
=13\ \text{references}+1\ \text{ablation}.
$$

另外可以生成两个分析别名：tuning-selected fixed policy 与 held-out offline oracle。别名不是额外的物理候选执行。

对每个冻结 cell，选择只使用 tuning prefix：

$$
k^*(u,s,\Delta,\rho)
=
\arg\min_{k\in\mathcal{K}_{\mathrm{ref}}}
C_{k,\mathrm{tune}}(\rho,b),
$$

并以规范候选 ID 作为唯一 tie break。得到 $k^*$ 后，它从自己的连续 post-tuning state 进入 held-out，不能重置状态，也不能在 held-out 重新选择。

offline oracle 仅表示“事后最好的固定候选”诊断下界：

$$
k^{\mathrm{oracle}}
=
\arg\min_{k\in\mathcal{K}_{\mathrm{ref}}}
C_{k,\mathrm{heldout}}.
$$

它不能进入主选择器，也不能被描述成在线混合策略。

# 完整成本模型

## 运算计数与实测常数分离

Day 1A 只产生因果运算计数。设闭合的 primitive 集合为 $\mathcal{P}$，某一候选在更新侧和查询侧的计数分别为 $n_{u,p}$ 与 $n_{q,p}$。Day 2 在 OpenFHE 上测量每个 primitive 的单位时间 $\theta_p$，则

$$
T_{u,\mathrm{compute}}
=\sum_{p\in\mathcal{P}}n_{u,p}\theta_p,
$$

$$
T_{q,\mathrm{compute}}
=\sum_{p\in\mathcal{P}}n_{q,p}\theta_p.
$$

Day 2 的点估计不是任意平均数，而是 14 个完整 measurement block 的中位数：

$$
\widehat{\theta}_p
=
\operatorname{median}
\left(
\theta_{p,1},\ldots,\theta_{p,14}
\right).
$$

偶数样本的定义也被冻结：将 14 个有效 block 值按升序写为 $\theta_{p,(1)}\le\cdots\le\theta_{p,(14)}$，则

$$
\widehat{\theta}_p
=\frac{\theta_{p,(7)}+\theta_{p,(8)}}{2}.
$$

任何缺失、额外或无效的完整 block 都使校准失败，而不是改用剩余样本。敏感性分析的每次 replicate 从 14 个 whole-block ordinal 中有放回地抽取 14 次；同一 ordinal 序列用于全部 primitive，并重新计算全部 $\widehat{\theta}_p$。

`config/params_manifest.json` 中历史 exploratory estimator 的 `measurement_repetitions=11` 不属于正式 Day 2 校准合同。正式证据只接受预注册的“三个 warm-up + 十四个完整 measurement block”路径；两者不能混合或用旧字段替代新 profile authority。

此前还有 3 个结构完全相同的 warm-up block，但它们不进入点估计。

## 通信成本

设每个接受的原始事件组对应更新侧规范序列化字节 $B_u$，每次查询对应查询侧字节 $B_q$。在带宽 $b$ Mbps 下，字节换算为秒：

$$
T_{\mathrm{net}}(B,b)
=
\frac{8B}{b\times 10^6}.
$$

$B_u$ 与 $B_q$ 必须来自实际规范序列化对象，包括元数据、查询、结果、随机 F1-M、dummy 和返回密文；不能只用“密文个数 × 猜测大小”。HTTP/TLS、文件系统、workflow 容器和 artifact wrapper 不进入冻结的协议事务范围。

## 主时间等价诊断

若查询/更新比为 $\rho$，主诊断是

$$
C(\rho,b)
=
T_{u,\mathrm{compute}}
+\frac{8B_u}{b\times 10^6}
+\rho\left(
T_{q,\mathrm{compute}}
+\frac{8B_q}{b\times 10^6}
\right).
$$

更新分母严格是一整个 accepted raw-event group。即使该组是 clipped no-op，或 T2 先 expiry 再 admission 产生两个 SET，它仍只贡献一个更新分母；该组导致的全部计算和发布成本都记入同一个分母。

这个公式解释了 break-even：当 $\rho$ 很小时，减少更新发布成本更重要；当 $\rho$ 很大时，额外 delta 查询成本会被放大。两策略 $a,b$ 的理论交点满足

$$
C_a(\rho^*,b)=C_b(\rho^*,b).
$$

若分母非零，可写为

$$
\rho^*
=
\frac{
T_{u,b}-T_{u,a}
+\dfrac{8(B_{u,b}-B_{u,a})}{b\times10^6}
}{
T_{q,a}-T_{q,b}
+\dfrac{8(B_{q,a}-B_{q,b})}{b\times10^6}
}.
$$

论文不会仅凭这个解析交点宣称胜利，而是在冻结的离散 $\rho$ 网格上做完整真实语料判决。

# 因果实验设计

这里的“因果”有严格的有限语料含义。对同一个冻结事件流 $\mathcal{E}_u$、相同初始状态、查询调度和公开参数，仅把维护策略从 $b$ 替换为 $a$，所比较的 estimand 是

$$
\tau_{a,b}(u,\rho,b_w)
=C_a(\mathcal{E}_u,\rho,b_w)
-C_b(\mathcal{E}_u,\rho,b_w).
$$

它是配对重放下的受控策略反事实，不是从三个数据集外推到任意部署或语料总体的平均因果效应。

## 查询到达的精确整数调度

冻结网格为

$$
\rho\in
\{0.01,0.03,0.1,0.3,1,3,10,30,100\}.
$$

对最简分数 $\rho=p/q$ 和从零开始的 accepted-event ordinal $a$，第 $a$ 个完整事件组后插入的查询数是

$$
Q_a
=
\left\lfloor\frac{(a+1)p}{q}\right\rfloor
-
\left\lfloor\frac{ap}{q}\right\rfloor.
$$

因此在 $N$ 个事件组后，查询总数精确为

$$
\sum_{a=0}^{N-1}Q_a
=
\left\lfloor\frac{Np}{q}\right\rfloor.
$$

该调度只依赖整数算术，不依赖候选结果、更新是否被裁剪、性能或 held-out 观察。

## 连续的 10/30/60 切分

对一个真实 trace 的 $N$ 个 accepted groups，冻结半开区间：

$$
\mathcal{I}_{\mathrm{warm}}
=[0,\lfloor N/10\rfloor),
$$

$$
\mathcal{I}_{\mathrm{tune}}
=[\lfloor N/10\rfloor,\lfloor4N/10\rfloor),
$$

$$
\mathcal{I}_{\mathrm{held}}
=[\lfloor4N/10\rfloor,N).
$$

对正式 tier $N=131072$，这三个区间精确实例化为

$$
[0,13107),\qquad[13107,52428),\qquad[52428,131072),
$$

长度分别是 13107、39321 和 78644，总和严格为 131072。

所有候选都从各自独立的 Strategy Snapshot 连续推进，不能在阶段边界恢复到初始布局。否则会抹掉 overflow、容量消耗和周期重压缩历史，产生不因果的比较。

## 真实语料与配对单位

固定的主语料为：

1. SNAP Stack Overflow 三种带类型的 temporal interaction；
2. Simple English Wikipedia 2026-07 MediaWiki History；
3. NYC TLC 2022 十二个月 yellow-taxi Parquet 加 zone lookup。

每个数据集使用两种更新语义：

- T1：累计 recurrence；
- T2：长度 $K=32768$ events 的 sliding window，先 expiry、后 admission。

再按 source entity 的规范哈希切成 5 个不相交分区，所以完整面板是

$$
3\ \text{datasets}
\times2\ \text{semantics}
\times5\ \text{partitions}
=30\ \text{paired units}.
$$

唯一 confirmatory family 是 T2、freshness $0.1$ s，共

$$
3\times5=15
$$

个固定 paired units。T1 和 freshness $1.0$ s 是预注册的 secondary panels，不能补救主结论。

每个 unit 目标是 131072 个 accepted raw events。映射只使用完整语料前缀的前 $\lfloor V/10\rfloor$ 个 schema-valid events；结果区使用后续事件。采用 65536 的小 tier 会使

$$
\left\lfloor\frac{4N}{10}\right\rfloor<K=32768,
$$

导致 tuning 阶段看不到一次 T2 expiry，而 held-out 突然切换机制，因此该 tier 被明确禁止。

T1 cumulative 语义可写为

$$
A_{uv}(t)=\min\{7,N_{uv}(t)\},
$$

所以它产生 Insert、Modify，以及达到上界后的 clipped no-op，不产生 Delete。T2 则维持最近 $K=32768$ 个 accepted events；窗口满时先让最旧事件 expiry，再 admission 新事件，因此同一 accepted group 可以产生零、一个或两个可见 SET。

# 主判决规则

## 相对改进

主比较基线是 `periodic-repack/windows=1`。对同一 unit、freshness 和 $\rho$，定义

$$
\delta
=
\frac{C_{\mathrm{recompress}}-C_{\mathrm{selected}}}
{C_{\mathrm{recompress}}}.
$$

必须有

$$
C_{\mathrm{recompress}}>0.
$$

所有比较使用规范整数、序列化字节和精确有理数；不使用二进制浮点 epsilon。正改进要求严格

$$
\delta>0,
$$

精确零也算失败。

## Pareto 非支配

对一个 held-out 点，用二元向量表示

$$
p_k=
\left(
\overline{B}_{u,k},
\overline{T}_{q,k}(1000\ \mathrm{Mbps})
\right).
$$

参考候选 $a$ 支配候选 $b$ 当且仅当

$$
p_a^{(1)}\le p_b^{(1)},
\qquad
p_a^{(2)}\le p_b^{(2)},
$$

且至少一个不等式严格成立。selected point 只有在 13 个冻结 references 中没有任何一个支配它时才是 non-dominated。

## headline 的全部条件

某个 $\rho$ 点通过固定语料规则，需要同时满足：

1. 15 个 unit 的 $\delta$ 全部可计算；
2. 15 个 unit 全部严格正改进；
3. 15 个 effect 排序后的第 8 个值满足

$$
\operatorname{median}(\delta_1,\ldots,\delta_{15})
\ge\frac{3}{20}=15\%;
$$

4. 每个 unit 的 selected point 都 non-dominated；
5. 完整候选、成本、重放、正确性和来源门禁全部通过。

最终 headline 还要求冻结网格中至少一对**相邻** $\rho$ 同时通过。例如 $(0.3,1)$ 可以，$(0.3,3)$ 不可以，因为中间跳过了 1。禁止插值或事后挑选连续区间。

## 为什么不做传统总体推断

5 个分区是确定性的 source-entity partitions，不是从总体中随机抽取的 15 个独立样本。窗口与查询也高度相关。因此论文报告每个 unit、median、IQR 和描述性 resampling sensitivity，但不把它们包装成总体置信区间，不做 sign test、$p$ 值或 Holm 调整。

另有 10000 次 Day 2 block-resampling 敏感性分析。每次复用同一个 block ordinal 序列来重算全部 primitive 中位数，从而保留跨 primitive 协方差，再重新选择 tuning winner、重算 effect 与 Pareto 分类。只有 10000 次 replicate 的分类都与点估计一致，headline 才能释放。

# 证据链为什么被设计得很严格

## 三类源快照

项目区分：

- Experiment Source Snapshot：真正执行实验的提交；
- Evidence-Freeze Snapshot：只安装已生成工件的 data-only anchor；
- Analysis Source Snapshot：执行最终验证器和分析器的提交。

三者不要求 SHA 完全相同，但差异必须由仓库拥有的 Behavior Set 和 compatibility receipt 证明只发生在允许的证据路径。普通 ancestor 关系、producer 自报文件清单或一个布尔 `verified=true` 都不够。

## S1 与 S2

在任何正式结果之前，所有会影响行为、决策规则、workflow、preregistration 和 analyzer 的文件先冻结为 pre-anchor S1。随后对该 S1 生成 registration evidence，并用单独的 data-only commit 安装唯一 anchor，形成 Terminal Registration Freeze S2。

当前 lineage 中：

- `S1 = b658e2178b210c2cc0012fc61957a3b3a92953bb`；
- 描述性 registration run 为 `33070626218`，其 51-entry Behavior Set digest 为 `d64dcfcd48e183736d4a6565cca8d698dbeef700d4cec0af4594b7258016d2b7`；
- `S2 = bb83d4e42209e24df0c71df3eea5df7cbff7e1d5`，且 S1 到 S2 只改变 `config/day1-registration-anchors.json`；
- S2 exact-head CI run `33073232432` 为 2118 passed、2 skipped。

S2 只安装 registration anchor，不授予未来 Day 1A、Day 2 或 Day 1B 结果权威。

## 四层实验角色

1. **R0 / correctness fixture**：证明某些冻结输入下 typed path 与 plaintext oracle 一致；
2. **Day 1A**：产生合成负载上的因果运算计数与 exact rotation inventory，不产生完整性能结论；
3. **Day 2**：在 OpenFHE 1.5.1 上测量闭合 primitive vocabulary 与实际序列化大小；
4. **Day 1B + R4**：在真实语料上用 frozen measured costs 选择/比较策略，并在合格点执行端到端密文正确性与 mixed-circuit 门禁。

因此必须保持三条边界：**测试通过不推出已经有论文性能结果；工作流成功不推出工件可采信；工件可重放也不推出 headline 条件已经通过。**

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

这个上限在真实语料路径中不是纸面假设：trace producer 逐事件维护 `peak_row_nonzeros`，超过 4096 就写入 `maximum-row-nonzeros-exceeded` eligibility failure；production trace consumer 重新播放 transition stream、重算峰值，并且只接受 `eligible=true`、空 failure list 的 131072-group bundle。策略状态转换还会在发布前再次拒绝超过 `max_row_nnz` 的候选逻辑状态。因此超限单元会 fail closed，而不会带着失效的 centered-lift 前提进入 Day 1B。

这只证明冻结整数边界下不存在模回绕歧义，不等价于 mixed-circuit 噪声预算安全。后者需要独立 OpenFHE 门禁。

# 论文真正可以声称什么

## 可以主张的贡献

1. 围绕静态 CSSC 的版本绑定可变维护语义；
2. 显式区分重叠求和、水平拼接和隐式零的私有 `OutputPlan`；
3. `OutputPlan` 驱动、只覆盖真实重叠且带持久 no-reuse identity 的 F1-M 集成；
4. 固定 $c=128$ strong delta 的 typed whole-query execution path；
5. 把独立持久候选状态、tuning-only selection、完整序列化成本和 commit-bound evidence 组合成 fail-closed 评估方法。

## 不能扩大成的主张

- 不是新的 BFV/FHE primitive；
- 不是第一个稀疏同态矩阵—向量乘法；
- 不是新的静态 CSSC；
- 不是首次 encrypted indices、隐藏 nonzero positions、双边稀疏 FHE 计算、版本承诺或随机输出 sharing；
- 不声称 formal security、malicious security、collusion security 或全侧信道保护；
- 不声称 $c=128$ 全局最优；
- 不声称在所有矩阵、数据集或 $\rho$ 上优于重压缩；
- 不把合成 Day 1A 计数当作真实语料性能；
- 不把 deterministic partitions 当作总体随机样本；
- 不在真实结果不满足规则时重新调参或删掉失败 unit。

如果主 headline 不通过，预注册允许的 fallback 是 benchmark/methodology 与边界刻画论文；不允许的 fallback 是看完 held-out 后修改门槛并继续声称原结论。

# 这篇论文的叙事主线

一篇清晰的最终论文可以按以下逻辑展开：

1. **静态格式的缺口**：CSSC 对静态稀疏模式有效，但更新会同时改变数据、列重排和结果映射；
2. **系统不变量**：提出 Publication Window 与原子版本提交，保证矩阵、布局、查询和重构同版本；
3. **多组件语义**：用 `OutputPlan` 明确重叠、拼接和隐式零；
4. **隐私化返回**：只对真实重叠应用一次性零和掩码，并持久绑定 no-reuse identity；
5. **可执行增量路径**：固定分段 strong delta 把统一 schedule 留给 Cloud，把逻辑行合并留给 Client B；
6. **策略不是免费午餐**：增量减少更新成本，却可能增加查询成本；
7. **用实测成本找边界**：Day 1A 提供计数，Day 2 提供 OpenFHE 单位成本，Day 1B 在真实语料上形成配对判决；
8. **结果无论正负都可解释**：若存在稳定相邻 $\rho$ 区域，报告其边界；若不存在，报告何时增量维护失去优势以及为什么。

# 当前进度与剩余工作

截至本文生成时，已经完成或建立的主要内容包括：

- 大部分 typed state、query compiler、`OutputPlan`、F1-M ledger、strong bundle、plaintext oracle、replay validator 与 workflow；
- S1/S2 registration lineage；
- S2 exact CI run `33073232432`：2118 passed，2 skipped；
- registration run `33070626218` 及其唯一 artifact、内部校验和、source/tree、专用 workflow provenance 和 51 个 Behavior Set Git blob 的独立复核；
- 跨 job pre-replay exact closed-tree/no-symlink/status-identity blocker 已由代码、测试和 ChatGPT Pro 窄审关闭；
- methods-first manuscript、preregistration、claim ledger 和 analysis isolation 框架。

本分支已把 `claim-ledger-draft.md` 中落后于当前 S2 anchor 的 strong candidate registration 状态同步为精确 S1/S2 范围内的 `PASS`。该状态只说明固定候选目录可以被仓库承认，绝不等于 formal Day 1A、完整成本或经验结果已经产生；C3 与所有经验 claim 仍保持 `HOLD`。

仍未形成最终论文结论的关键项是：

1. 当前 NON-ADMISSIBLE 单分片 Day 1A 诊断 run `33075408647` 必须先通过；
2. 正式 21-shard Day 1A 与 aggregate 必须产生并被接纳；
3. Day 2 calibration、profile/post-run anchors 必须闭合；
4. 三个真实数据源的 acquisition、transform、30 unit manifests 和 TRACE anchor 必须闭合；
5. Day 1B production adapter 与 resource HOLD 必须关闭；
6. Day 1B、mixed-circuit、R4 与 S3 analysis 必须完成；
7. 最终结果、图表、局限性、声明、数据可用性和 DOI 才能写入 submission-ready manuscript。

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
- `docs/paper/publication-preregistration-draft.md`
- `docs/paper/publication-roadmap.md`
- `docs/paper/claim-ledger-draft.md`
- `docs/protocol-patch-v2.1b.md`
- `docs/decisions/0003-f1m-hidden-rowmap.md`
- `docs/decisions/0005-output-plan-overlap-blinding.md`
- `docs/decisions/0006-persistent-strategy-snapshots.md`
- `docs/decisions/0007-anonymous-fixed-segment-primitive.md`
- `docs/decisions/0008-strong-whole-query-execution-bundle.md`
- `docs/decisions/0010-separate-experiment-and-evidence-freeze-snapshots.md`
- `docs/decisions/0012-window-weighted-day1b-accounting.md`
- `config/experiment_plan_publication.json`
- `config/params_manifest.json`

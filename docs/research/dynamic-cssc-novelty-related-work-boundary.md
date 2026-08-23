# Dynamic CSSC-SpMV：一手材料下的新颖性与相关工作边界

核验日期：2026-08-22
核验源码树：merged `main` `fcb00e0d7f111f3ab5003c111b124df83ae11813`
目的：为论文的贡献表述、Related Work 和 claim gate 划定可审计边界；不替代系统性专利检索、正式 novelty opinion、密码学证明或实验结果。

## 1. 核验范围与证据规则

本报告只使用两类材料：

1. 本仓库在上述提交上的一手项目材料，主要是 [`methods-and-claims-skeleton.md`](../paper/methods-and-claims-skeleton.md)、[`protocol-patch-v2.1b.md`](../protocol-patch-v2.1b.md)、[`architecture.md`](../architecture.md)、ADR 0003/0005/0006/0007/0008 和 `config/params_manifest.json`；
2. 原论文、作者预印本/技术报告、会议或期刊官方页面、作者代码，以及与 manifest 固定提交一致的 OpenFHE 官方源码。

没有用综述、博客、聚合摘要或二手解读来建立 prior-art 结论。检索重点是：

- 静态的 FHE/HE 稀疏 SpMV；
- 明文域动态稀疏格式与 base/delta、slack、overflow、重排/切换；
- 支持更新的加密数据库与 epoch/padding/flush 机制；
- 可抵消一次性掩码；
- OpenFHE 中打包、旋转和 rotation-key 的现成能力。

“未在本次一手材料中找到直接相同机制”只表示一个**候选新颖点**，不等于“全球首次”。尤其是 2026 年文献仍在快速增加；在没有系统性数据库、专利和引用链检索前，论文不得使用 `first`、`only`、`unprecedented` 或中文等价措辞。

## 2. 结论先行

### 2.1 最强但必须收窄的贡献边界

本项目当前最有希望成立的贡献，不是新的静态稀疏格式，也不是“首次在密文上更新矩阵”，而是以下机制在 **CSSC 的可变、多组件查询路径**中的联合设计：

1. 以 Publication Window 把可变逻辑矩阵提交为不可变、可查询版本，并强制 CSSC 组件、全局 `ColumnIndex`、查询准备、`OutputPlan` 和重构使用同一 `version_id`；
2. 用 RowMap-sensitive `dynamic-cssc-output-plan-v1` 显式描述多组件、多输出块到逻辑坐标的映射，并区分相同坐标求和、互斥块拼接和无贡献坐标的隐式零；
3. 在重叠逻辑坐标上集成一次性零和掩码、五元组绑定和持久化防复用账本；Cloud-facing OutputPlan 投影不携带 RowMap，但 Cloud 仍见公布的形状、数量、调度、时序、查询/版本标识和绑定摘要；
4. 为强 delta 路径定义不透明标识符定宽段、客户端合并 leader，以及把真实 CSSC base、delta、私有路由、操作数与承诺绑定为一个 fail-closed whole-query bundle；该 ACL 不构成段之间不可关联/不可推断的证明；
5. 用相互独立、跨 Publication Window 持久演化的策略快照和分层证据规则，避免用 held-out 信息或离线 oracle 污染策略选择。

这是一组**面向动态 CSSC 的系统/协议协同设计候选**。各组成概念大多已有先例，候选新意在于它们对 CSSC 的精确组合、版本不变量和泄漏边界，而不是组成概念本身。

### 2.2 现在可以写什么

当前可写入论文的是：动机、相关工作、系统与威胁模型、方法定义、协议不变量、设计局限，以及“仓库在指定提交上实现/规定了某接口或 gate”的 commit-scoped 描述。

当前不能把论文写成已经成立的效率或安全性论文。仓库自己把结果稿标为 HOLD：没有当前提交的 R2 Day 1 artifact，没有完整 reference set，强 Packed-COO 候选仍未注册，manifest 的 mixed-circuit 参数未冻结，没有 Day 2 测量、R4 端到端证据或形式化安全证明。若现在投稿，最诚实的定位是**方法/协议与可复现实验设计稿**；若目标是常规 SCI/SCIE/EI 的完整实验论文，还缺核心实证。

### 2.3 必须避免的宽泛主张

- 不能称“首个双密文稀疏 SpMV”。Lodia 已在 ACM CCS 2025 给出矩阵与向量都加密的示例协议，并证明该示例协议在其模型下对半诚实对手安全；它早于 CSSC 的 2026 论文。
- 不能称“首个动态加密数据库/首个密文更新”。FHE 数据库已有 encrypted conditional `UPDATE`；动态 SSE 和 oblivious transaction 系统也早已研究更新、版本状态、padding、flush 和 epoch commit。
- 不能把 row sorting、slicing、reserved slack、COO overflow、base+delta、周期合并或格式选择分别宣称为新概念。
- 不能把零和掩码本身宣称为新密码学原语。
- 不能把 OpenFHE 的 SIMD、`EvalRotate` 或 rotation-key generation 当作贡献。
- 不能宣称安全性强于 Lodia；Lodia 已给出固定电路下的结构隐藏分析和示例协议证明，而本项目目前没有对应证明。

## 3. 从仓库材料还原出的准确贡献对象

静态 CSSC substrate 必须归属于 Gao et al.。本项目不是作者代码复现；现有措辞应保持为“依据公开伪代码独立重构”。

| 层次 | 准确内容 | 当前归属与状态 |
|---|---|---|
| 静态 substrate | 按非零数排序行、左对齐、列主序提取，`Value/ColumnIndex/RowMap/ColumnPointer`，按 chunk 重组 query，chunk 内与跨 chunk 聚合 | Gao et al. CSSC；只引用，不主张 |
| 动态状态 | Publication Window、提交版本、版本匹配的 Published Components 和 freshness 约束 | 本项目的系统设计候选；可写设计，效果未验证 |
| 多组件语义 | 版本化 `OutputPlan`、logical-coordinate contributor multiplicity、隐式零、重叠求和与互斥块拼接 | 本项目最强的协议/接口候选之一；可写设计，端到端未验证 |
| F1-M | overlap-only 一次性零和掩码，五元组绑定，持久化原子 reserve/reject ledger | 组合设计候选；零和 masking 本身非新，安全有效性 HOLD |
| 强 delta | 公共定宽、2 幂段；Cloud 对每段固定归约到 leader；同行等价字段仅携带在 Client B 的 typed plan 中，且不主张不可关联性 | 当前 exact-source whole-query fixture 已通过 pinned OpenFHE witness；候选仍未注册，完整成本与 R4 仍缺 |
| 执行绑定 | 一个 bundle 绑定真实 CSSC base、strong delta、typed DAG、私有 route、全局列号 operand、计数和 commitment | 可作为可审计系统工程贡献；不是新的 HE primitive |
| 评估纪律 | 策略独立因果快照、tuning-only fixed policy、offline oracle 仅作诊断、设计/预测/测量/端到端证据分层 | 方法学与可复现性贡献；不宜包装为核心算法新颖性 |

`docs/task-v2.1-original.md` 是保留的历史任务书，不是当前协议的最高权威。它关于“不要声称首次密文更新/动态 layout，Mini-CSSC 直接组合不新”的谨慎要求与本次文献边界一致；最终论文应分别绑定实验源快照 S1、证据冻结快照 S2 和分析源快照 S3，并通过 ADR 0010 的角色化 Behavior Set 兼容凭据消费证据。

## 4. 最接近的一手相关工作

### 4.1 静态、加密的稀疏 SpMV

#### CSSC：直接 substrate，同时明确留下动态更新空位

Gao et al. 的 [CSSC 论文](https://arxiv.org/html/2603.04742v1)（[期刊 DOI](https://doi.org/10.1016/j.ins.2026.123180)）定义了 `CSSC(M)=(VA,CI,RM,CP)`、行排序/左对齐、原列号、RowMap、chunk 化 query reorganization 和静态聚合路径。其结论明确把静态稀疏模式列为限制，并把避免完全重压缩的增量更新作为未来方向。

因此，本项目可以准确写成“在公开 CSSC substrate 周围设计 update-aware maintenance layer”。这条作者自述说明问题确实未被 CSSC 本身解决，但**不能单独证明本项目是首个解决者**。

CSSC 原文还在“稀疏结构公开”和“Cloud 不得获知位置”之间存在表述冲突；本项目的 Client B/Cloud ACL 应明确归属于 v2.1b，而不是声称继承了一个无歧义的 CSSC 安全模型。

#### Lodia：早于 CSSC 的强静态对手，阻断广泛的 first/security claim

Yu et al. 的 [Lodia](https://eprint.iacr.org/2025/1425)（[ACM CCS 2025 DOI](https://doi.org/10.1145/3719027.3765025)）用 low-diagonal decomposition 支持任意稀疏矩阵，给出 `Theta((n+m) log(n+m) / s)` 的 FHE 操作复杂度。其 setting 中 matrix owner 明文持有矩阵并发送加密表示，server 持有加密向量；附录示例协议同时加密 `A` 和 `x`。固定计算路径只依赖公开尺寸和填充后的非零数，并给出示例两方协议的半诚实安全证明。

边界是：Lodia 是静态矩阵编码和静态 SpMV，不是 CSSC 的增量维护协议；本项目仍可在“mutable CSSC maintenance”上形成差异。但 Lodia 必须进入 Related Work，并至少作为不同泄漏/电路代价下的强概念基线。当前项目不能写“首个双密文稀疏 SpMV”“首个隐藏精确稀疏结构的 SpMV”或“安全性优于现有方法”。

#### Diagonal Packing：2026 年新增的静态 layout/compiler 竞争面

Mutluergil et al. 的 [Diagonal Packing / 2DPP](https://arxiv.org/html/2604.04683v2) 通过同时重排行列来减少 Halevi–Shoup 方法中的 occupied cyclic diagonals，并把方法定位为 encrypted linear algebra 的 compiler-level optimization；其 v2 于 2026-07-09 修订，晚于 CSSC 初稿但早于本次核验。论文当前只处理方阵，且没有动态更新协议。

边界是：它不覆盖本项目的版本化可变 CSSC，但阻断“首次为 HE SpMV 做矩阵重排”“首次做 HE-aware compiler/layout optimization”之类表述。由于其时间很新，最终论文必须显式讨论，不能只复用 CSSC 原论文的 Related Work。

#### Ferguson et al.：FHE 中 CSR/ELLPACK 类稀疏方案并非新概念

Ferguson et al. 的 [EuroMLSys 2025 论文](https://arxiv.org/html/2503.09184)（[DOI](https://doi.org/10.1145/3721146.3721948)）提出三种基于常见明文稀疏编码的 FHE matrix-multiplication 方案，并讨论为了跳过零而暴露 sparsity pattern 的代价。它针对 DNN/matmul、静态输入和不同威胁面，不是动态 CSSC SpMV。

边界是：用 CSR/ELLPACK/packed sparse operand 加速 FHE 的宽泛想法已有先例。强 Packed-COO 的候选差异必须落在**使用不透明标识符的定宽段、Cloud-side segmented reduction、版本化客户端合并和 whole-query binding**，不能只落在“FHE + COO/segment”；当前证据不建立段不可链接性或同行等价隐藏。

### 4.2 明文动态稀疏格式与存储：阻断对组成机制的过度主张

- Kreutzer et al. 的 [SELL-C-sigma](https://arxiv.org/abs/1307.6209) 把 sliced ELLPACK、局部行排序和 padding 组合为带调参项的 SpMV 格式。CSSC 自身另有明确归属，但本文仍不能把“行排序 + 切片/填充”泛化为新的动态贡献。
- Bell and Garland 的 [CUDA SpMV 技术报告](https://mgarland.org/files/papers/nvr-2008-004.pdf) 研究 ELL/COO 等格式及其混合取舍。HYB 的核心是规则 ELL 部分加不规则 COO overflow；因此 `Packed-COO-HYB-Delta` 这个名字本身不建立新颖性。
- King et al. 的 [Dynamic-CSR](https://thomas.gilray.org/pdf/dynamic-csr-extended.pdf) 直接针对异步动态更新：CSR 插入通常需要重建，ELL 预留固定容量，COO 易更新但 SpMV 慢，HYB 用 COO 处理 overflow；DCSR 再用每行可增长 segment 和额外空间支持后续插入。它直接阻断 reserved slack、segment overflow、局部扩容和 update/query trade-off 的宽泛新颖性主张。
- O'Neil et al. 的 [LSM-tree 原论文](https://dsf.berkeley.edu/cs286/papers/lsm-acta1996.pdf) 通过内存组件、磁盘组件、批量延迟变更和滚动 merge 平衡写入与查询。Mini-CSSC delta、base+delta、多层 component 和 periodic repack 可以是对 CSSC 的具体实现，但不能被描述为新的 base/delta/compaction 思想。
- Stylianou and Weiland 的 [Morpheus](https://arxiv.org/abs/2209.06478) 提供动态稀疏矩阵抽象和运行时格式选择。因果评估、固定 policy 和迁移成本的精确控制仍有方法学价值，但“依据 workload 在多种稀疏格式间选择”不是新的宽泛命题。

这些工作都不提供 FHE CSSC 的版本/重构协议，所以它们是**概念归属边界**，未必是可直接比较的 encrypted runtime baseline。

### 4.3 动态加密数据系统：更新、padding、epoch 和 state binding 不是空白地带

Parbat and Chatterjee 的 [Authorized Update in Multi-User Homomorphic Encrypted Cloud Database](https://doi.org/10.1109/TKDE.2022.3221148) 在 FHE 数据库中支持带访问控制的加密 conditional SQL `UPDATE`。它不是稀疏 SpMV，也不维护 CSSC layout，但足以排除“首次在 FHE 加密数据上支持更新”的说法。

Vo et al. 的 [ShieldDB](https://arxiv.org/abs/2003.06103) 面向持续更新的 encrypted document database，联合使用 padding、forward privacy、re-encryption 和 flushing；它采用 searchable encryption 而不是 FHE。Cash et al. 的 [NDSS 2014 Dynamic SSE](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/dynamic-searchable-encryption-very-large-databases-data-structures-and-implementation/) 更早形式化并实现了可搜索、可更新的加密数据库。

Crooks et al. 的 [Obladi](https://www.usenix.org/conference/osdi18/presentation/crooks) 在 oblivious transaction 系统中以 epoch 批量执行事务并延迟到 epoch 末决定 commit。它不是 FHE SpMV，却说明 publication/commit window、固定可见节奏和 epoch 原子性不能作为孤立的新概念。

本项目与这些工作的可守差异是：它要保持 CSSC 的查询语义，并把可变稀疏矩阵版本、全局列号 query gather、多组件 RowMap 重构和 F1-M output shares 同时绑定。Related Work 应写“借鉴/对应于更广泛动态加密系统中的 batching、state 和 leakage-management 问题”，而不是暗示动态加密数据此前不存在。

### 4.4 零和掩码：原语已知，作用域和绑定才可能是项目差异

Bonawitz et al. 的 [Practical Secure Aggregation](https://acmccs.github.io/papers/p1175-bonawitzA.pdf) 已明确使用成对的一次性加/减随机向量，使掩码在总和中抵消而个体输入不直接暴露。因此“zero-sum masking”不是本项目的新密码学原语。

本项目可能有差异的是：依据私有 `OutputPlan` 的逻辑坐标 contributor multiplicity，只在真实重叠处生成随机零和 shares，对不重叠返回使用拼接或固定 encrypted-zero operand，并把每个随机 mask 绑定到 `(query_id, version_id, output_plan_digest, component_id, output_block_id)` 的持久化防复用语义。该差异目前只能称**应用特定的 masking integration/design**；在 R4 和正式证明之前不能称 secure aggregation protocol、simulation-secure 或已证明阻止泄漏。

### 4.5 OpenFHE：实现底座，不是论文新颖点

manifest 固定 OpenFHE 1.5.1 提交 `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`。该提交的官方材料已经提供：

- packed integer 上的逐槽加法/乘法和 cyclic rotation（[encoding 文档](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/docs/sphinx_rsts/modules/pke/pke_encoding.rst#L40-L48)）；
- `EvalRotate` 调用已生成 automorphism keys 并委托 `EvalAtIndex`（[`cryptocontext.h`](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/include/cryptocontext.h#L2295-L2306)）；
- 对明确 rotation index 列表生成 evaluation keys（[`cryptocontext.h`](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/include/cryptocontext.h#L2449-L2475)；
- BFVRNS 的显式 rotation 示例（[`rotation.cpp`](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/examples/rotation.cpp#L73-L115)）。

所以论文贡献只能是这些 primitive 的 CSSC-specific schedule、key plan、binding 和测量，不是 primitive 本身。抽象 rotation node 数也不能自动等同于 primitive key-switch 数、wall time 或 noise；这些都需要 pinned OpenFHE artifact。

## 5. Claim-by-claim 新颖性矩阵

状态含义：

- **可写-设计**：可以在当前 manuscript 的 Methods/Related Work 中按指定范围陈述；不能暗示已测量或已证明。
- **补证后可写**：候选差异合理，但需要指定 artifact、对照或证明。
- **暂缓**：当前仓库状态不足。
- **禁止作新颖点**：已有直接或明确的组成 prior art；只能引用/归属。

| # | 候选 manuscript claim | 最接近的一手边界 | 当前可守表述 | 还缺什么 | 状态 |
|---:|---|---|---|---|---|
| 1 | 本文提出 CSSC、行排序、chunk 和 query reorganization | CSSC 原论文已完整定义这些机制 | 本文以独立伪代码重构的静态 CSSC 为 substrate | 正确引用即可；不得写作者代码 reproduction | **禁止作新颖点** |
| 2 | 首个双密文/加密稀疏 SpMV | Lodia CCS 2025 的矩阵/向量加密示例协议早于 CSSC 2026；Ferguson 等也已研究 FHE sparsity | 不作 first claim；把静态 FHE SpMV 放入背景 | 无合理短期补证路径可支持该宽泛主张 | **禁止作新颖点** |
| 3 | 首个动态加密 SpMV / 首个 dynamic CSSC | CSSC 明确把 evolving sparsity/incremental update 留作未来工作；本次未在核验的静态 FHE SpMV 一手材料中发现 CSSC-specific mutable protocol，但 FHE DB、DSSE 已有更新 | “我们设计一个围绕静态 CSSC 的 update-aware maintenance layer” | 扩大系统性检索；明确操作语义；与 full recompression 和最接近动态组合逐项比较 | **可写-设计**；`first` **暂缓** |
| 4 | Publication Window、版本一致性和 freshness 是新机制 | Obladi 已有 epoch commit；动态 SSE 有 client state/update；版本/原子可见性并非新概念 | 贡献在于把这些不变量绑定到 CSSC components、CI、query gather、OutputPlan 和 reconstruction | 当前提交 R0/R2；版本错配/超时/rollback 负例；端到端可见性证据 | **补证后可写** |
| 5 | PaddingReuse、ReservedSlack、Strict LocalRepack 是新动态格式 | SELL-C-sigma、ELL/HYB、DCSR 已有 padding、fixed capacity、overflow、per-row segments 和局部增长 | 把它们标为 maintenance comparison families | 公平成本定义和测量；不需要 novelty claim | **禁止作新颖点** |
| 6 | Mini-CSSC delta、PeriodicRepack 的 base+delta/compaction 是新概念 | LSM-tree 已有多 component、deferred batched changes、merge；HYB 已有 regular base + COO overflow | 这是 CSSC-specific baseline/composition | 与 full recompression、delta growth 和 query amplification 的因果对照 | **禁止作宽泛新颖点** |
| 7 | packed COO 或 fixed segments 本身是新的 | COO/HYB、DCSR segments、Ferguson 的 FHE sparse formats 都提供组成 prior art | 候选差异只限定为不透明标识符定宽段 + Cloud segmented reduction + private client merge + version binding；不主张段不可关联 | 当前提交 whole-query witness；candidate registration；对 leakage/操作数的逐项比较；R4 | **暂缓** |
| 8 | RowMap-sensitive multi-component `OutputPlan` 与重构规则 | CSSC 只有静态单矩阵 `RowMap`；本次核验未见相同的动态多组件 plan | “本文规定一个版本化私有 plan，区分重叠求和、互斥块拼接和隐式零” | 对所有策略的 property tests、错绑 fail-closed 证据、R4 全路径正确性；扩展检索 | **可写-设计 / 补证后可强化** |
| 9 | 零和 masking 是新密码学技术 | Bonawitz 等已使用可抵消一次性掩码 | 贡献候选是 overlap-scoped、OutputPlan-derived、五元组绑定和 no-reuse ledger 的 CSSC-specific integration | R4 encrypted masks/dummies、crash/replay traces、通信/内存开销和正式泄漏证明 | 原语 **禁止作新颖点**；集成 **暂缓安全 claim** |
| 10 | F1-M 隐藏 RowMap/拓扑，或安全性优于现有方法 | Lodia 对 server 隐藏精确位置并有示例协议证明；本项目 Client B 明知 CI、RowMap 和完整 plan，Cloud 仍见 shapes/counts/schedule/timing/digest | “F1-M 的预期保密目标是限制 Client B 分离重叠 component values；Cloud 接口禁止 RowMap 字段”——当前证据均不证明该目标已实现 | 明确定义 ideal functionality/leakage；模拟器与证明；R4 与攻击/消融 | **暂缓** |
| 11 | 因果 persistent snapshots、fixed policy 或 offline oracle 是新算法 | Morpheus/自动格式选择说明 selection 非新；避免 held-out leakage 是实验纪律 | 把它作为可信评估方法，不作为主要算法贡献；offline oracle 仅是诊断 bound | 当前提交 R2 replay receipts；tuning/held-out 分离；迁移/并行维护成本若允许 switching | **可写-设计** |
| 12 | whole-query execution bundle / provenance 是新 HE primitive | 没有 primitive 层差异；它是系统 binding 和 artifact discipline | 可作为“fail-closed executable specification / reproducibility mechanism” | 当前提交的独立 witness、tamper negative tests、R4；避免把 artifact schema包装成密码学新颖性 | **可写-设计 / 补证后可强化** |
| 13 | corrected stored-power/prefix DAG 或 OpenFHE rotation 是新算法 | CSSC 引用的 `totalSum` 路线和 OpenFHE rotation/key generation 已存在；本仓库只是纠正/统一 paper-intended schedule | 写成“用于避免非 2 幂字面错误并统一 simulator/adapter 的实现修正” | 当前提交 correctness witness；primitive key plan、noise 和时间测量 | **禁止作宽泛新颖点** |
| 14 | 某策略更快、更省内存/带宽，或动态维护优于 full recompression | 当前没有 R2/Day 2/R4；reference set 不完整 | 不给任何胜负、Pareto、速度或端到端成本结论 | 完整基线 R2、Day 2、mixed-circuit gate、R4、多数据集/更新分布/seed | **暂缓** |
| 15 | 比较覆盖全部强基线，或方法优于 SOTA | strong Packed-COO 未注册；Lodia 和 2026 Diagonal Packing 必须纳入相关工作边界 | 当前不报告比较结果；角色合同禁止 partial-reference artifact，并区分不可直接比较的 leakage/shape/settings | 冻结复合注册锚、完成 14/13/1 R2；决定 Lodia/2DPP 的实验可比性并给出同威胁模型对照；更新检索 | **暂缓** |
| 16 | OpenFHE 参数已证明安全且适合 mixed workload | 官方源码只说明 primitive；manifest 自己标记 mixed-circuit parameterization unfrozen | 只报告固定版本、配置和已通过的窄 gate | mixed-circuit decryption correctness、noise margin、key plan、重复测量和 provenance | **暂缓** |

## 6. 建议的论文贡献表述

### 6.1 当前可用的窄表述

下面这段与现有证据边界一致，可以作为后续摘要/Introduction 的工作底稿；在没有对应 artifact 时必须保留“design/specify”，不要换成“demonstrate/achieve/outperform”。

> We design an update-aware maintenance layer around the published static CSSC representation. The layer commits mutable sparse-matrix state at freshness-bounded publication boundaries and binds each query to version-matched CSSC components, global-column query metadata, and a RowMap-sensitive reconstruction plan. For multi-component results, the protocol distinguishes logical-coordinate overlap from disjoint output blocks and specifies overlap-scoped one-time masking with persistent no-reuse bindings. We further define an opaque-identifier fixed-segment delta path and a fail-closed whole-query execution bundle that binds the static base, delta program, private routes, operands, and operation counts. The typed Cloud plan omits RowMap and same-row-equivalence fields, but no segment-unlinkability claim is made. Performance, end-to-end masking effectiveness, and formal security are evaluated only after their commit-bound evidence gates pass.

中文可概括为：

> 本文围绕已发表的静态 CSSC 表示设计一个可更新维护层。该层在 freshness-bounded publication boundary 提交矩阵版本，并将 CSSC 组件、全局列号查询元数据、私有 RowMap-sensitive 重构计划和结果 shares 绑定到同一版本。对于多组件结果，协议显式区分逻辑坐标重叠与互斥输出块，并规定重叠作用域的一次性掩码及持久化防复用语义。本文还定义使用不透明标识符的定宽 delta 路径和 fail-closed whole-query execution bundle；这是接口 ACL，不是段之间不可关联性证明。效率、端到端掩码有效性与形式化安全性只在对应的 commit-bound gate 通过后报告。

### 6.2 推荐的贡献拆分

1. **系统语义贡献**：CSSC-specific publication/version/freshness contract，而不是一般意义的 epoch 或 versioning。
2. **接口与正确性贡献**：版本化、RowMap-sensitive 多组件 `OutputPlan`，包括 contributor multiplicity、implicit zero、overlap-add 和 disjoint-concatenate。
3. **隐私协议集成贡献**：在该 plan 上进行 overlap-only masking、固定可见 operand 位置和 no-reuse binding；不要把 zero-sum masks 本身称为新。
4. **执行与证据贡献**：不透明标识符固定段 strong delta 及 whole-query fail-closed binding；在当前证据补齐前称“specified/implemented candidate”，不称“validated baseline”，不主张段之间不可关联。
5. **评估方法贡献**：因果快照、separate deterministic replay 与严格证据分层；replay 可检测 artifact 篡改/非确定性，但复用生产 evaluator，不是独立实现 oracle。

## 7. 投稿前必须补的证据

### 7.1 最低可发表的正确性闭环

- 当前 `fcb00e0d` 的 R0 已通过；后续快照只有在该证据角色的冻结 Behavior Set 发生漂移时才必须重跑，纯证据锚或分析层变更必须通过 ADR 0010 的 S1/S2/S3 兼容验证。P0a 仍是历史 scoped evidence，不能外推到最终 key inventory。
- 生成当前提交的 R2 Day 1 artifact：精确 layout preflight、跨 window 持久策略状态、separate deterministic replay receipts 和 checksum 均需通过。
- 保留并归档当前 `fcb00e0d` 的 Phase 2 whole-query witness（run `32581653504`，artifact SHA-256 `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`）；该角色的 Behavior Set 任何后续变更都必须产生新 witness，而不是沿用该 receipt。
- 为版本错配、过期 query、tampered plan digest、错误 global `ColumnIndex`、重复 mask binding、crash-after-reserve 和 disjoint-block accidental add 提供 fail-closed 负例。

### 7.2 最低可发表的比较闭环

- 首要动态 baseline 必须包含“每个 Publication Window 完整重压缩静态 CSSC”；否则不能量化 dynamic layer 的收益。
- 保留 PaddingReuse、ReservedSlack、Mini-CSSC delta、client-lane COO、LocalRepack、PeriodicRepack 的 baseline 身份，不把它们包装为新格式。
- 注册并验证真正的 Cloud-segmented strong Packed-COO，才能把 `complete_reference_set` 改为 true。
- Related Work 必须加入 Lodia 和 2026-07 的 Diagonal Packing。实验上若因矩阵形状、泄漏或电路模型不能直接比较，应给出明确 incompatibility table，而不是省略。
- 主分析严格使用预注册的三数据集、两种语义、freshness/rho 网格、
  microbatch 合同和唯一 query-vector seed。任何额外 freshness、microbatch
  或 seed 只能在 held-out 前另行预注册为描述性敏感性面板，不能授权、
  替代或救援 headline；单一 4096-by-8193 manifest 下的结论仍须明确其范围。

### 7.3 最低可发表的成本与安全闭环

- 冻结 mixed-circuit 参数，完成 decryption correctness/noise margin gate，再做 Day 2 OpenFHE 重复测量；分别报告抽象 DAG node、primitive key switch、rotation-key set、时间和内存。
- 完成 R4：真实 BFVRNS ciphertext 下的 base+delta query、encrypted random masks、encrypted-zero dummies、ledger/batch-token trace、Client B 解密/重构、通信和内存原始计数。
- 若论文使用“prevents leakage”“secure”“simulation-based”等强词，必须另给 ideal functionality、泄漏函数、模拟器和定理；测试与 R4 不能替代证明。
- 安全比较应把 Lodia 单列：它隐藏 server 所见的精确 sparsity pattern，而本项目允许 Client B 看见 CI/RowMap/plan，Cloud 还可见形状、计数、调度、时序和摘要。两者不能只用“都半诚实”粗略等同。

## 8. 应长期保持暂缓或永久排除的 claim

即使工程实现继续完善，下面的表述也不应仅靠当前路线自然“升级”为可发表结论：

- “首个 encrypted/double-ciphertext sparse SpMV”；
- “首个支持密文更新或动态加密数据的系统”；
- “首次提出 row sorting、slicing、reserved slack、COO overflow、base+delta、periodic compaction、epoch commit 或 zero-sum masking”；
- “CSSC 作者实现的 reproduction”；
- “F1-M 隐藏全部拓扑/访问/流量模式”；
- “Client B 不知道 RowMap/OutputPlan”；
- “形式化安全”“simulation-secure”或“安全性强于 Lodia”，除非另有完整证明与同模型比较；
- “全基线/SOTA 比较”以及任何端到端、系统或部署层面的策略胜负，直至 strong candidate 注册、reference set 完整且 R2/Day 2/R4 对应 gate 通过；没有 R4 时只可报告明确限定为 fixed-corpus calibrated-component diagnostic 的结果；
- 把抽象 rotation 数写成 exact key-switch、runtime、noise 或 parameter-safety 结论。

## 9. Related Work 可直接采用的组织方式

建议按问题边界而不是按算法名单组织：

1. **Static encrypted sparse linear algebra**：先讲 Lodia 的 low-diagonal/structure-hiding 路线、CSSC 的 sparse-coordinate compression 路线、Ferguson 的 FHE sparse encodings、Diagonal Packing 的 cyclic-diagonal compiler optimization；明确本文不再提出静态格式。
2. **Dynamic sparse storage and maintenance**：SELL-C-sigma、ELL/HYB、DCSR、LSM-tree、Morpheus；说明本文借用的 slack/overflow/delta/compaction/selection 思想已有历史，差异在 encrypted CSSC query path 的版本化编译与重构。
3. **Dynamic encrypted data systems**：FHE conditional update、Dynamic SSE、ShieldDB、Obladi；说明 publication window 和 leakage management 的跨域先例，同时指出它们不执行 ciphertext–ciphertext CSSC SpMV。
4. **Result-share privacy**：引用 secure aggregation 的 canceling masks；把 F1-M 定位为 plan-scoped integration，而不是新 masking primitive。
5. **Implementation substrate**：OpenFHE 只放实现章节或 artifact appendix，清楚区分 library capability 与本文 schedule/binding。

一个稳妥的 related-work 收束句是：

> Prior work separately addresses static encrypted SpMV, mutable plaintext sparse layouts, and continuously updated encrypted databases. Our scope is narrower: we specify how mutable CSSC components become version-consistent query inputs and how their encrypted partial outputs are reconstructed under an explicit leakage contract. We do not claim novelty for the underlying CSSC layout, slack/delta/compaction families, epoch batching, or canceling masks.

## 10. 一手来源清单

### 直接的 encrypted sparse SpMV / sparse FHE

- Yang Gao et al., *Efficient Privacy-Preserving Sparse Matrix-Vector Multiplication Using Homomorphic Encryption*, Information Sciences 739 (2026) 123180: [arXiv HTML](https://arxiv.org/html/2603.04742v1), [DOI](https://doi.org/10.1016/j.ins.2026.123180).
- Jiping Yu et al., *Lodia: Towards Optimal Sparse Matrix-Vector Multiplication for Batched Fully Homomorphic Encryption*, ACM CCS 2025: [IACR ePrint](https://eprint.iacr.org/2025/1425), [DOI](https://doi.org/10.1145/3719027.3765025).
- Kemal Mutluergil et al., *Diagonal Packing for Efficient Homomorphic Sparse Matrix-Vector Multiplication*: [arXiv v2](https://arxiv.org/html/2604.04683v2).
- Aidan Ferguson et al., *Exploiting Unstructured Sparsity in Fully Homomorphic Encrypted DNNs*, EuroMLSys 2025: [author preprint](https://arxiv.org/html/2503.09184), [DOI](https://doi.org/10.1145/3721146.3721948).
- Jiaxing He et al., *Rhombus: Fast Homomorphic Matrix-Vector Multiplication for Secure Two-Party Inference*, ACM CCS 2024: [IACR ePrint](https://eprint.iacr.org/2024/1611), [DOI](https://doi.org/10.1145/3658644.3690281).
- Marc Damie et al., *Secure Sparse Matrix Multiplications and their Applications to Privacy-Preserving Machine Learning*: [arXiv](https://arxiv.org/abs/2510.14894). This is an MPC/secret-sharing comparison, not an FHE-CSSC baseline.

### 动态稀疏格式与存储

- Moritz Kreutzer et al., *A Unified Sparse Matrix Data Format for Efficient General Sparse Matrix-Vector Multiply on Modern Processors with Wide SIMD Units*: [arXiv](https://arxiv.org/abs/1307.6209).
- Nathan Bell and Michael Garland, *Efficient Sparse Matrix-Vector Multiplication on CUDA*, NVIDIA Technical Report NVR-2008-004: [author PDF](https://mgarland.org/files/papers/nvr-2008-004.pdf).
- James King et al., *Dynamic-CSR: A Format for Dynamic Sparse-Matrix Updates*: [author PDF](https://thomas.gilray.org/pdf/dynamic-csr-extended.pdf).
- Patrick O'Neil et al., *The Log-Structured Merge-Tree (LSM-tree)*, Acta Informatica 33 (1996): [original-paper mirror](https://dsf.berkeley.edu/cs286/papers/lsm-acta1996.pdf), [DOI](https://doi.org/10.1007/s002360050048).
- Chris Stylianou and Michele Weiland, *Exploiting Dynamic Sparse Matrices for Performance Portable Linear Algebra Operations*: [arXiv](https://arxiv.org/abs/2209.06478).

### 动态加密系统与掩码

- Tanusree Parbat and Ayantika Chatterjee, *Authorized Update in Multi-User Homomorphic Encrypted Cloud Database*, IEEE TKDE 35(8): [DOI](https://doi.org/10.1109/TKDE.2022.3221148).
- Viet Vo et al., *ShieldDB: An Encrypted Document Database with Padding Countermeasures*: [arXiv](https://arxiv.org/abs/2003.06103), [author implementation](https://github.com/MonashCybersecurityLab/ShieldDB).
- David Cash et al., *Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation*, NDSS 2014: [official proceedings page](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/dynamic-searchable-encryption-very-large-databases-data-structures-and-implementation/).
- Natacha Crooks et al., *Obladi: Oblivious Serializable Transactions in the Cloud*, OSDI 2018: [official USENIX page](https://www.usenix.org/conference/osdi18/presentation/crooks).
- Keith Bonawitz et al., *Practical Secure Aggregation for Privacy-Preserving Machine Learning*, ACM CCS 2017: [conference PDF](https://acmccs.github.io/papers/p1175-bonawitzA.pdf), [DOI](https://doi.org/10.1145/3133956.3133982).

### 固定实现底座

- OpenFHE 1.5.1 pinned source commit `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`: [repository tree](https://github.com/openfheorg/openfhe-development/tree/1306d14f8c26bb6150d3e6ad54f28dfe1007689e), [packed encoding](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/docs/sphinx_rsts/modules/pke/pke_encoding.rst#L40-L48), [`EvalRotate`](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/include/cryptocontext.h#L2295-L2306), [rotation-key generation](https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/include/cryptocontext.h#L2449-L2475).

## 11. 最终判断

这个项目有一个可发表的窄问题：**如何把静态 CSSC 变成版本一致、可审计、具有明确泄漏边界的多组件可更新查询系统**。目前最像论文贡献的是版本化 `OutputPlan`、多组件重构语义、F1-M 的 CSSC-specific binding，以及不透明标识符固定段 delta 与 whole-query bundle 的联合设计；这不构成段之间不可关联性声明。

当前 exact-source R0 与 Phase 2 fixture correctness 已经通过，但能诚实发表的仍是设计、方法边界和该窄正确性事实，不是效率、安全或 SOTA 结论。最重要的下一步不是扩大宣传，而是完成强基线 admission、R2/Day 2/R4、真实数据与统计证据，并把 Lodia 与 2026 Diagonal Packing 纳入最新相关工作。完成这些之前，论文题眼应是 **update-aware extension around CSSC**，而不是 **first dynamic encrypted SpMV**。

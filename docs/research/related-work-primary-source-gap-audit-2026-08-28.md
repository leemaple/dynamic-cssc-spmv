# Dynamic CSSC-SpMV Related Work 一手来源缺口审计（2026-08-28）

核验截止：2026-08-28（Asia/Shanghai）

起点材料：[`dynamic-cssc-novelty-related-work-boundary.md`](./dynamic-cssc-novelty-related-work-boundary.md) 与 [`references.bib`](../paper/references.bib)

用途：确定最终 Related Work、新颖性边界和实验 baseline 的最低要求；不直接修改论文或书目。

## 1. 证据规则与结论

本次只采用论文/作者预印本、出版社或会议官方页面、作者/机构论文存档和官方代码仓库。检索集中在 2023--2026 年的 FHE/HE 稀疏 SpMV/SpMM、可更新加密数据、动态稀疏格式、state/epoch/version binding，以及会直接限制本文 claim 的 masking/secure aggregation。下面每一项把来源直接放在事实旁边，并明确区分：

- **已核验事实**：来源明确写出或其算法/实验直接给出；
- **推断/边界**：由已核验事实对本文 claim 或实验可比性作出的判断，不冒充原作者结论；
- “本次未发现同机制”只是截至该日期、上述来源范围内的检索结论，**不是全球首次证明**。

结论如下。

1. 现有边界文档的主结论仍成立：可守的新颖性不是静态 sparse packing、一般意义的密文更新、epoch、padding、格式切换或 canceling masks，而是 **围绕静态 CSSC 的可更新维护层**，尤其是版本匹配的 components/query/RowMap-sensitive `OutputPlan`、多组件重构、overlap-scoped mask binding，以及 fail-closed whole-query binding。
2. 但最终 Related Work 目前有三项实质性的 2026 稀疏 FHE 缺口：**CipherSkip、SparseE、D'Agata et al. 的 GPU SpMSpM**。前两项尤其阻断任何“首次隐藏 encrypted indices/稀疏位置”或“首次在 FHE 中利用双边稀疏性”的宽泛说法。
3. 动态/泄漏边界还应加入 **d-DSE**；如果正文把 version/freshness binding 当作贡献，应加入 **Chen et al. 的 CKKS-Auth Tree**。它们不解决 SpMV，却分别说明 update-volume leakage 和 versioned commitment/replay rejection 已有直接先例。
4. 截止本次核验，已检查的一手材料中**没有找到同时满足**“结构插入/删除或变更 + FHE sparse layout 增量维护 + 版本化发布 + SpMV 多组件重构”的论文。这支持窄的 gap statement，但不足以支持 `first`/`only`。
5. 当前 4096-by-8193、BFVRNS/OpenFHE 的冻结主实验域见 [`experiment_plan_publication.json`](../../config/experiment_plan_publication.json) 与 [`params_manifest.json`](../../config/params_manifest.json)。在该域中，唯一必须直接比较的外部 substrate baseline 是“每个发布窗口完整重建静态 CSSC”；Lodia 可以成为条件式静态 comparator，其余近邻应为单独静态敏感性实验或 citation-only，而不能被伪装成同任务动态 baseline。

## 2. 真正会重塑新颖性边界的五项缺口

### 2.1 CipherSkip（ICS 2026）：最大的直接缺口

**已核验事实。** Xiong et al. 的 [CipherSkip 一手全文与元数据](https://eprint.iacr.org/2026/297)（[ACM DOI](https://doi.org/10.1145/3797905.3807876)）发表于 ICS 2026。它处理 FHE sparse general matrix--matrix multiplication（SpGEMM），支持任意矩阵形状；客户端在加密前对非零项做 alignment，发送加密的 value vectors 和 index vectors。论文的半诚实 client/server 模型声称 server 除公开扩展长度 $L$ 与矩阵维度外，不获知稀疏矩阵的值和位置。实现使用 Pyfhel/CKKS，并把 Lodia 按输出列重复执行作为一项比较。论文中的 “dynamic server-side alignment” 指链式矩阵乘法中对**加密中间结果**的对齐与去重，不是随时间演化矩阵的 insert/delete/update；全文没有定义 publication version、增量 sparse-layout maintenance 或跨版本查询/重构协议。

**推断/边界。** CipherSkip 直接阻断以下说法：

- “首次在 FHE 稀疏矩阵计算中加密/隐藏 indices 或 nonzero positions”；
- “首次在不暴露稀疏位置的情况下利用 sparsity”；
- “首次支持任意形状的结构隐藏 FHE sparse matmul”。

它没有消除本文的窄差异：CipherSkip 的对象是一次静态 SpGEMM/链式乘法，而不是围绕 CSSC publication windows 的状态维护、版本匹配和 RowMap-sensitive 多组件重构。该判断是**任务边界推断**，不是 CipherSkip 作者的新颖性结论。

**论文动作。** 最终 Related Work 和 `references.bib` 必须新增 `xiong2026cipherskip`（authors、ICS 2026、pp. 1220--1231、DOI `10.1145/3797905.3807876`）。当前主实验中它是 citation-only；只有另行冻结“把 length-8193 query 当作 8193-by-1 第二矩阵”的静态比较、统一 scheme/library/parameters/corpus 和计费边界后，才可作为**静态条件式 comparator**，且不能回答动态维护问题。

### 2.2 SparseE（DAC 2026）：encrypted-index 与硬件协同设计的直接竞争面

**已核验事实。** DAC 2026 [官方 research-manuscript 页面](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108)列出 Wei et al. 的 *SparseE: Unlocking Sparsities in Encrypted Sparse Matrix Multiplication via Hardware-Software Co-Design*。官方摘要明确给出：FHE sparse SpMM、secure Scatter--Gather--Apply、以 encrypted indices 驱动的 homomorphic permutation network、计算量随 nonzeros 变化并保护 sparsity pattern，以及专用 permutation/expansion accelerator。北航的[作者机构发布页](https://bhkj.buaa.edu.cn/info/1013/10833.htm)确认同一作者列表与机制方向。

**已核验的不确定性。** 截止核验日，会议公开页只提供标题、作者和摘要；本次一手检索没有找到可公开访问的出版社全文、DOI 或官方代码。因而当前**不能核验** SparseE 的完整 leakage function、输入加密角色、矩阵形状限制、参数、代码可用性，也不能断言其有或没有 mutable update/version protocol。

**推断/边界。** 可公开核验的材料已足够阻断“encrypted-index Scatter/Gather 或 permutation-based sparse FHE 是本文首次”的说法；但它尚不足以否定本文的 CSSC-specific mutable-maintenance gap。缺少全文时，不能把“摘要未提更新”写成“论文没有更新协议”。

**论文动作。** 最终 Related Work 必须讨论 SparseE；`references.bib` 先新增 `wei2026sparsee` 的**临时 `@misc` 会议程序项**，只填作者、题目、DAC 2026、官方 URL 和访问日，不得虚构 DOI/页码。出版社记录出现后再升级为 `@inproceedings`。由于任务是 SpMM、平台是专用硬件且公共全文/实现/参数未落地，当前只能 citation-only。

### 2.3 D'Agata et al.（EuroMLSys 2026）：公开结构的 GPU ciphertext--ciphertext SpMSpM

**已核验事实。** D'Agata et al. 的 [arXiv 全文](https://arxiv.org/abs/2604.11659)（[ACM DOI](https://doi.org/10.1145/3805621.3807642)，[作者机构正式记录](https://eprints.gla.ac.uk/385854/)）把 Ferguson et al. 的 ciphertext--ciphertext sparse matmul 扩展到 AMD GPU/FIDESlib。它使用 CKKS，评估 CSR/CSC 和 VCSR/VCSC 组合；为跳过零，row pointers、indices 或 sparsity masks 等 metadata 保持明文。实验是随机生成的 8-by-8 与 16-by-16 方阵 proof-of-concept，并明确不把 format conversion、encoding 和 encryption 纳入 matmul runtime。论文没有 structural-update 或 versioned-publication 协议。

**推断/边界。** 它进一步证明“FHE + CSR/CSC/VCSR sparse encoding”“ciphertext--ciphertext 双边稀疏 matmul”以及该方向的 GPU 加速都不是本文可以主张的宽泛新意；但其公开 sparsity metadata、CKKS、SpMSpM、小方阵和 GPU 目标与本文 BFVRNS、动态 SpMV、矩形真实语料不同。

**论文动作。** 最终 Related Work 和 `references.bib` 必须新增 `dagata2026gpu`（EuroMLSys 2026, pp. 155--162, DOI `10.1145/3805621.3807642`）。主实验 citation-only；不能用其论文 runtime 与本文数字直接作速度比。

### 2.4 d-DSE（USENIX Security 2024）：padding 不是 update leakage 的充分答案

**已核验事实。** Liu et al. 的 [d-DSE 官方论文页](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli)定义 Distinct Dynamic Searchable Encryption，处理 search/update queries、volume-hiding、forward privacy 与 backward privacy；论文明确指出 padding countermeasures 会显著增加 storage/communication cost，并设计不同的 volume-hiding 路线。

**推断/边界。** d-DSE 不是 FHE 或 SpMV，不能作为 runtime baseline；但它直接约束本文的 leakage 语言。固定段、固定可见 schedule、dummy 或 padding 只能按**明确 leakage function 与已测成本**描述，不能写成“解决了动态更新泄漏”。若正文保留 Cloud 可见 shapes/counts/schedule/timing，这些必须明确列入泄漏面。

**论文动作。** 最终 Related Work 和 `references.bib` 应新增 `liu2024ddse`（USENIX Security 24, pp. 2563--2580, 官方 URL）。它是 citation-only，用于限定 leakage claim，不进入 SpMV 性能图。

### 2.5 CKKS-Auth Tree（Chen et al., Electronics 2026）：versioned commitment 与 stale/replay rejection 已有先例

**已核验事实。** Chen et al. 的 *Retrieval Integrity Verification Mechanism with Privacy Protection and Dynamic Updates for Blockchain Oracles*（[出版社全文](https://www.mdpi.com/2079-9292/15/12/2517)，[DOI](https://doi.org/10.3390/electronics15122517)）提出 CKKS-Auth Tree，支持 encrypted metadata 的 insert/modify/delete；更新沿受影响的树路径传播，smart contract 保存 versioned root commitments 与 timestamps，使用户能够检测 stale/replayed verification objects。出版社正文还描述了提交新 root、version、timestamp 与 update type。这里不把论文未在摘要中列出的其他具体字段扩写成本文的事实前提。

**推断/边界。** 它不是 sparse linear algebra，也不提供 CSSC query semantics；但足以阻断“版本化承诺、freshness check 或 replay rejection 本身为首次”的说法。本文可守差异必须是这些不变量对 CSSC components、global-column query metadata、私有 RowMap-sensitive reconstruction 和 output shares 的**具体联合绑定**。

**论文动作。** 只要最终贡献列表保留 version/freshness/state binding，就必须在 Related Work 与 `references.bib` 新增 `chen2026ckksauthtree`（*Electronics* 15(12), 2517, DOI `10.3390/electronics15122517`）。它只作 citation-only。

## 3. 现有点名工作的边界复核

| 工作 | 已核验事实 | 对现有边界的裁决与必要修正 | 实验身份 |
|---|---|---|---|
| [CSSC](https://arxiv.org/html/2603.04742v1)（[DOI](https://doi.org/10.1016/j.ins.2026.123180)） | 定义静态 `VA/CI/RM/CP`、行排序/左对齐/列主序与 chunk query；结论明确把 static sparsity 与避免 full recompression 的 incremental update 列为未来工作。原文一处称零/非零位置向所有参与方公开，随后又称 Cloud 不获知位置/indices/RowMap，而 Client B 可获知 column-wise pattern。 | **基本准确，但必须保留歧义说明。** 不应把 CSSC 原文当成无歧义 leakage contract；本文的 Client B/Cloud ACL 与泄漏清单应明确归属本文协议。静态 substrate 必须归 Gao et al.。 | **直接且必须**：每个 publication window 完整 CSSC recompression/re-encryption，使用同一实现、参数、语料和成本边界。 |
| [Lodia](https://eprint.iacr.org/2025/1425)（[DOI](https://doi.org/10.1145/3719027.3765025)） | 任意 sparse matrix 的 low-diagonal decomposition，FHE 操作复杂度为 $\Theta((n+m)\log(n+m)/s)$；server 侧得到加密矩阵表示和加密向量，结构隐藏到公开尺寸/填充规模。实验使用 OpenFHE 1.2.3 的 BFV/BGV/CKKS。半诚实 simulation-style 证明属于附录给出的具体两方协议；核心 primitive 本身给出相同规模矩阵的 server-view indistinguishability 目标。没有 matrix-state update/publication/version protocol。 | **准确，但证明归属需写细。** 可以说“Lodia 的附录示例协议在其半诚实模型下给出证明”，不要笼统说所有可能集成都已证明。它阻断双密文/结构隐藏 SpMV 的 broad-first claim，但不覆盖 mutable CSSC maintenance。 | **条件式静态 comparator**：可在同一 OpenFHE 版本、BFVRNS 参数、形状、语料、计费和 leakage contract 下移植；不是动态维护 baseline。 |
| [Diagonal Packing / 2DPP](https://arxiv.org/html/2604.04683v2) | 静态重排行列以减少 occupied cyclic diagonals，定位为 encrypted SpMV 的 compiler optimization，并明确给出 both-sides-encrypted outsourced-server 场景。场景 1/3 中 server/client 可能推断占用的 diagonal-index set，但不知道各 diagonal 内的精确 nonzero positions。当前只支持方阵，矩形扩展是 future work；没有结构更新协议。 | **准确。** residual diagonal-set leakage 是论文明示事实，不应降格为推断；同时也不能误写成逐坐标 sparsity pattern 公开。它阻断 HE-aware row/column reordering 或 compiler/layout 的宽泛新意。 | 当前 4096-by-8193 主实验 **citation-only**；可另行预注册 square/static sensitivity panel，不能补作动态 baseline。 |
| [Ferguson et al.](https://arxiv.org/html/2503.09184)（[DOI](https://doi.org/10.1145/3721146.3721948)，[官方代码](https://github.com/aidan-ferguson/sparse-fhe-matmul)） | Microsoft SEAL/CKKS 的 ciphertext--ciphertext **SpMSpM**，含 naive sparse、CSR、ELLPACK；数值加密，零位图/row/column indices 等 sparsity metadata 为明文。主实验为 8-by-8，扩展至 16-by-16/32-by-32 小方阵；无 update protocol。 | **准确，但最终稿必须显式写 SpMSpM 而非 SpMV，并写明 public indices/pattern。** 它阻断“FHE + CSR/ELLPACK/packed sparse operand”作为新概念。 | **citation-only**：operation、CKKS/SEAL、shape/corpus 与动态任务均不一致；官方代码可用于概念核查，不应直接生成同任务速度比。 |
| [Rhombus](https://eprint.iacr.org/2024/1611)（[DOI](https://doi.org/10.1145/3658644.3690281)） | 半诚实两方 secure MVM：Bob 持有明文 matrix/model，Alice 持有并加密 vector；Bob 同态计算后抽取随机 share，Alice 解密另一 share，输出 additive shares。其 MVM protocol 没有定义 sparse storage/layout 或结构更新机制。 | **现有边界比 CSSC 对 Rhombus 的二手描述更准确。** 应称 general plaintext-matrix/ciphertext-vector secure MVM，不应把“structured sparsity”归给 Rhombus。它还阻断“首次以随机掩码把 MVM 输出变成 additive shares”；本文差异只能是 overlap-scoped、多组件、版本绑定与 no-reuse ledger。 | **citation-only**：plaintext matrix、两方 inference、share-output 与本文双密文动态 CSSC 不同。 |
| [FHE database update](https://doi.org/10.1109/TKDE.2022.3221148)、[Dynamic SSE](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/dynamic-searchable-encryption-very-large-databases-data-structures-and-implementation/)、[ShieldDB](https://arxiv.org/abs/2003.06103)、[Obladi](https://www.usenix.org/conference/osdi18/presentation/crooks) | 分别覆盖 encrypted conditional SQL `UPDATE`、可更新 searchable encryption、持续更新下 padding/flush/re-encryption、epoch batch/commit；新增 d-DSE 进一步覆盖 update-volume leakage。 | **准确，但应补 d-DSE。** 这些工作足以排除一般意义的 encrypted update、epoch、padding、state 作为新概念；本文差异是它们与 CSSC query/reconstruction 的具体结合。 | 全部 **citation-only**：功能、威胁模型、查询和成本单位不同。 |
| [SELL-C-sigma](https://arxiv.org/html/1307.6209) | sliced ELLPACK，chunk height $C$，在 sorting scope σ 内按 row length 排序并 padding，以改善 SIMD/SIMT SpMV。 | **准确。** 只用于归属 row sorting/slicing/padding；它是 plaintext static HPC format，不是 dynamic/encrypted maintenance。 | **citation-only**。 |
| [Morpheus](https://arxiv.org/html/2209.06478)（[官方仓库](https://github.com/morpheus-org/morpheus)） | `DynamicMatrix` 在 COO/CSR/DIA 等 concrete formats 间运行时 `activate()`/convert，并按 operation、hardware 和 sparsity pattern dispatch；HPCG 的 timed optimized problem 先在 setup 构造矩阵，随后不做结构变更。库支持 diagonal value update，但论文没有 insertion/deletion 式 sparsity evolution。 | **准确，但应把 “dynamic” 释义为 runtime format switching。** 它限制“workload-aware sparse-format selection”新颖性，不构成 insertion/deletion 或 publication-version prior art。 | **citation-only**。 |

### 3.1 masking 与 secure aggregation 的最小边界

现有 `references.bib` 中 [Bonawitz et al.](https://doi.org/10.1145/3133956.3133982) 已足以归属 canceling/zero-sum masks 这一原语；Rhombus 又直接展示 MVM 输出通过随机减法转换为 additive shares。因此无需再堆一般 secure-aggregation 文献。最终稿只应把候选差异写为：由私有 `OutputPlan` 决定真实 overlap coordinates，按 `(query_id, version_id, output_plan_digest, component_id, output_block_id)` 绑定一次性 shares，并用持久 ledger 防止复用。没有形式化 leakage function/simulator 时，不得升级为通用 secure-aggregation 或 simulation-security claim。

## 4. 哪些方法可以实验比较

“可比较”要求至少统一 task semantics、matrix/vector encryption roles、HE scheme/library/version、安全参数、矩阵形状与语料、预处理/加密/通信是否计入、线程/硬件和 leakage contract。只比较论文中的已发表 wall-clock 数字不满足要求。

| 等级 | 方法 | 可比较内容 | 裁决与理由 |
|---|---|---|---|
| A：主实验直接 baseline | 静态 CSSC full recompression | 每个 publication window 从当前逻辑矩阵重建、加密、查询与重构的总成本 | **必须执行。** 同一 substrate、任务、实现、参数、语料与动态语义；这是判断增量维护是否值得的必要 counterfactual。 |
| A：主实验内部 baseline | 已注册的 full rebuild、reuse/slack/local repack、base+delta/periodic repack 等维护 families | update/query/space/freshness trade-off | **可直接比较**，前提是 reference set、计费与证据 gate 完整；这些是本文内部比较，不是外部新颖性归属。 |
| B：条件式静态 comparator | Lodia | 固定矩阵、固定 query 的 encrypted SpMV runtime/memory/communication 与 leakage | **优先级最高的外部 comparator。** 它已用 OpenFHE 且覆盖 BFV，但必须移植到同一 pinned version/parameters/shape/corpus，并分别报告 preprocessing/encryption。它不能比较 update maintenance。 |
| B：独立静态敏感性 | 2DPP | square matrices 上 diagonal layout 与静态 CSSC 的 query cost | 只有另行预注册 square subset、统一 HE 参数与泄漏说明后才可；不适用于冻结的 4096-by-8193 headline。 |
| B/C：条件式静态或仅引用 | CipherSkip | 把 dense-ish query 视为 n-by-1 第二矩阵时的静态 computation | 当前应 citation-only；若独立实现并统一 BFVRNS/OpenFHE、shape/corpus、CKKS equality 替代与全部成本，可做探索性静态 panel。仍不是动态 baseline。 |
| C：citation-only | Ferguson、D'Agata | 双边 sparse ciphertext matmul 的设计空间 | SpMSpM、CKKS、公开结构、小型合成方阵，且后者是 GPU/FIDESlib；与主任务不具同质性。 |
| C：citation-only | SparseE | encrypted-index SpMM 与 hardware/software co-design | 公共全文/实现/参数尚不可核验，且为专用硬件 SpMM；不能做公平 runtime comparison。 |
| C：citation-only | Rhombus | plaintext-matrix/ciphertext-vector secure MVM 与 output shares | 不同输入保密角色、协议输出和应用目标。 |
| C：citation-only | d-DSE、Chen et al.、FHE DB/DSSE/ShieldDB/Obladi | update leakage、version/freshness、padding/epoch 先例 | 不同功能与成本单位；只约束 claim/leakage discussion。 |
| C：citation-only | SELL-C-sigma、Morpheus、Dynamic-CSR、LSM-tree | plaintext format、slack/overflow、format switching、base/delta/merge 的概念归属 | 无 FHE/本文威胁模型，不能成为 encrypted runtime baseline。 |

## 5. 最终 Related Work 与 `references.bib` 的最小动作表

| 优先级 | 建议 key | 一手来源与最低元数据 | Related Work 动作 | baseline 动作 |
|---|---|---|---|---|
| **P0 必须新增** | `xiong2026cipherskip` | Xiong, Zhou, Ye, Jin, Xu; *CipherSkip*; ICS 2026; pp. 1220--1231; [DOI](https://doi.org/10.1145/3797905.3807876); [ePrint](https://eprint.iacr.org/2026/297) | 放入 static encrypted sparse linear algebra；明确 encrypted positions、arbitrary-shape SpGEMM 与无 mutable publication protocol。 | 当前 citation-only；条件式静态 panel。 |
| **P0 必须新增** | `wei2026sparsee` | Wei, Wang, Bian, Jin, Zhao; *SparseE*; DAC 2026 research manuscript; [官方程序](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108) | 放入 encrypted-index/hardware co-design；明确全文尚未公开核验，避免补写未知细节。 | citation-only。 |
| **P0 必须新增** | `dagata2026gpu` | D'Agata et al.; EuroMLSys 2026; pp. 155--162; [DOI](https://doi.org/10.1145/3805621.3807642); [作者存档](https://eprints.gla.ac.uk/385854/) | 接在 Ferguson 后，说明 GPU/FIDESlib、public metadata、SpMSpM。 | citation-only。 |
| **P0（当前 leakage scope 下必须）** | `liu2024ddse` | Liu et al.; USENIX Security 24; pp. 2563--2580; [官方页](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli) | 放入 dynamic encrypted data/leakage；限制 padding/fixed schedule 的安全措辞。 | citation-only。 |
| **P0（当前 version contribution 下必须）** | `chen2026ckksauthtree` | Qinghuan Chen et al.; *Electronics* 15(12), 2517; [DOI](https://doi.org/10.3390/electronics15122517) | 放入 state/version/freshness binding；说明跨域先例与 CSSC-specific 差异。 | citation-only。 |
| P1 条件新增 | `chowdhury2025sparsefhe` | Chowdhury, Bauer, Zhou; *Efficient Privacy-Preserving Recommendation on Sparse Data using Fully Homomorphic Encryption*; IEEE eScience 2025; pp. 1--9; [DOI](https://doi.org/10.1109/eScience65000.2025.00010); [arXiv](https://arxiv.org/html/2509.03024) | 只有当 Introduction/Related Work 使用“first FHE+CSR”或泛化到 encrypted sparse data 时加入；该工作只加密 values，row/column indices 公开，并由可信 CSP 把 masked ratings 转成 CSR。 | citation-only。 |
| 保留并修正文案 | 现有 keys | CSSC、Lodia、2DPP、Ferguson、Rhombus、SELL-C-sigma、Morpheus、Parbat、Cash、ShieldDB、Obladi、Bonawitz | 按第 3 节修正任务、泄漏与证明归属；无需重复新增 key。 | 按第 4 节分类。 |

`wei2026sparsee` 在公开出版社元数据出现前不应填写猜测的 DOI、页码或 publisher。表中其余已经给出的 DOI、页码或官方会议信息均已由对应 publisher、conference 或 ePrint 页面核验。

## 6. 最终稿可守与不可守的收束句

### 6.1 可守表述

> Prior work covers static encrypted sparse SpMV/SpMM with either public or encrypted structural metadata, as well as mutable plaintext sparse formats and dynamically updated encrypted databases. We address a narrower gap: an update-aware maintenance layer around static CSSC that binds version-matched components and query metadata to a RowMap-sensitive multi-component reconstruction plan, with overlap-scoped one-time output sharing and fail-closed execution bindings. We do not claim novelty for sparse packing, encrypted indices, epoch batching, padding, format switching, versioned commitments, or canceling masks in isolation.

### 6.2 必须排除或进一步收窄

- 不得写“首个 FHE sparse SpMV/SpMM”“首个双密文 sparse computation”；Lodia、CSSC、Ferguson/D'Agata 和 CipherSkip 已覆盖不同子类。
- 不得写“首个隐藏 sparsity pattern / encrypted indices”；Lodia、CipherSkip 与 SparseE 已直接进入该边界。
- 不得写“首个动态加密数据、epoch、version/freshness binding”；FHE database、DSSE/ShieldDB/Obladi、d-DSE 和 CKKS-Auth Tree 已提供先例。
- 不得把 fixed segments/padding/dummies 写成完整的 update-leakage 防护，除非给出明确 leakage function、攻击面和成本结果。
- 不得把 random output share/zero-sum mask 本身写成新密码学原语；Rhombus 与 Bonawitz 已足以归属。
- 可以写“we design/specify an update-aware maintenance layer around static CSSC”；如要写 “to our knowledge, the first”，仍需另做系统性数据库、引用链和专利检索，并把检索协议与日期公开。当前材料不支持该升级。

## 7. 检索后的低优先级项

- [Chowdhury et al. 2025](https://arxiv.org/html/2509.03024) 会阻断“FHE + CSR/sparse data 首次”的过宽措辞，但它是应用特定 matrix factorization、公开 indices 且含可信 CSP，不改变本文的 mutable CSSC 核心边界；因此只在出现该宽泛措辞时加入。
- [Compilation of Dynamic Sparse Tensor Algebra](https://doi.org/10.1145/3563338)（作者[论文 PDF](https://tensor-compiler.org/files/chou-oopsla22-taco-dynamic.pdf)）支持 evolving sparsity、动态数据结构和 compiler-generated assembly，但发表于 2022，且不含加密/版本化查询。若最终稿把贡献扩张为“首个动态 sparse compiler”，应补引；按当前窄表述不是 P0。
- 本次没有把 dense FHE matmul、一般 ORAM、一般 secure aggregation 或不涉及 sparse/update/version 的 FHE database paper 堆入清单，因为它们不会进一步改变当前已经收窄的 claim。

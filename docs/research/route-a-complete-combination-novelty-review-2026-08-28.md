# Route A 完整组合的一手来源新颖性审计

检索截止：**2026-08-28**（Asia/Shanghai）

主裁决：**PASS — 仅对本文件定义的完整组合碰撞检查**

保留裁决：**HOLD — `first`、`only`、全球首次、专利新颖性或形式化安全性**

## 1. Commit-bound 审计对象

- 仓库基线提交：`3249d5c122ed1545f47a802348eeb0dd6464c0f1`
- 分支：`codex/day1a-no-go-paper-pivot`
- Route A 审计稿：
  [`publication-preregistration-route-a.md`](../paper/publication-preregistration-route-a.md)
- Route A 最终候选 SHA-256：
  `232cd9d9599b56ffa62f108dcf1bf268e59031c8206fb0ebcf1e9a742ddfc5d7`
- Route A 最终候选行数：`1486`
- 起点边界报告 SHA-256：
  `0984b0c7f537c40cff852b3662f5f866c37f4eed227b286e4db89f428fed8925`
- 起点 `references.bib` SHA-256：
  `b802875d149d299edd88b13d850d3b99eef8c5b26a3924f1ab9b988bde0d0164`

基线提交是源码归属锚；Route A 文件在审计时仍未提交，因此以上精确内容哈希固定
本次审计对象。第 2 节独立冻结本次文献碰撞检查的四条件 claim vector。后续若
贡献句、四个组成条件、候选文件内容或引用截止日改变，本裁决不会自动继承，必须
重新核验。

本次外部 material-gate 修订仅关闭 retry attempt identity、投影目标证据、初始
状态、字节权威、查询向量、冻结顺序和证明义务；逐字复核 §1.1 与 §2.1--§2.5 后，
冻结贡献句以及 C1--C4 组合向量均未改变。因此重新绑定上述候选字节，不重开宽泛
文献检索；任何贡献句或 C1--C4 漂移仍会使本 PASS 失效。

基准 Stage-1 提交后的首次实现前阅读发现，payload-free tick 与 query-bearing
Publication Window 的切分可被解释成两种行为。本次窄澄清只固定同一逻辑时间、
tick 不独立触发 microbatch 关闭，以及有查询时由同一个窗口同时承载 pending SET
与 `query_count`；它不改变贡献句、C1--C4、威胁模型、证据矩阵、数据源或成本声明。
因此只需对澄清后的精确候选重新绑定并复核，无需重开文献搜索；若复核发现上述
任一 novelty-bearing 元素漂移，本 PASS 仍立即失效。

第二次实现前阅读进一步固定有限迹末尾 pending SET 的一次终端发布、query-only
窗口不递增版本也不产生更新侧维护或加密工作的规则，并统一 inclusive event-group
range 端点与 SET-reference 顺序。这些都是窗口与版本的记账闭合，不改变贡献句、
C1--C4、角色与威胁模型、数据源、证据矩阵或成本声明；
因此本次仍只重新绑定精确候选字节并复核 novelty-bearing 段落，不重开一手来源
检索。

第三次实现前审查只澄清短期 provider `NON-EVIDENCE` transport 位于私有证据
admission boundary、保留 exact preparation/consumed-ledger bytes 供只读 replay，且
这些私有字节不进入协议 Cloud 或正式工件。逐字复核贡献句、§2.1 角色边界以及
§2.2--§2.5 的 C1--C4 后，没有新增机制、放宽威胁模型或改变组合 claim vector；
因此仅重新绑定精确候选字节，不重开文献检索。任何 novelty-bearing 文本漂移仍使
本 PASS 失效。

第三次实现前阅读发现，窗口内同一坐标的多次 SET 可被解释为逐次物理应用，或先
归约为一个首值到末值的净更新；两种解释会改变成本记账。本次窄修订明确采用项目
既有 Publication Window 的共同净更新语义，分开保留 accepted-SET 与 net-update
计数，并固定 SET-bearing 净零窗口的三策略物理与版本元数据规则。这会关闭成本协议
歧义，但不改变贡献句、C1--C4、角色与威胁模型、数据源、证据矩阵、比较候选或永久
非声明；45/55/60 分钟和 12 小时门槛也未放宽。因此本次仍只重新绑定精确候选字节
并复核 novelty-bearing 段落，无需重开一手来源检索；任何上述元素漂移仍立即使本
PASS 失效。

本次 native q3/q4 material-gate 窄修订只把已由 producer 生成但此前未作为
retained object 保存的 exact serialized CryptoContext 加入私有 replay package，
并把相同的 Cloud-program 操作清单与 producer/replay 各自不同的 lifecycle 操作
清单分开。它没有改变贡献句、C1--C4、动态 CSSC 机制、查询重组、RowMap 重构、
F1-M mask 作用域、角色/威胁模型、数据源、比较候选或论文声明；CryptoContext、
secret key、ledger 与 oracle bytes 仍是证据传输开销而非新增 Cloud 协议机制。
因此对 §1.1、§2.1--§2.5 的本地逐字复核支持仅重新绑定精确候选字节，不重开
一手来源检索；任何 novelty-bearing 漂移仍会使本 PASS 失效。

## 2. 本次判定的“完整组合”

只有一篇既有论文或一个既有系统在同一设计中同时覆盖以下四项，才算对本次
Route A 贡献发生**完整组合碰撞**：

1. **C1 — mutable CSSC publication**：从可变逻辑矩阵产生不可变、可查询的
   CSSC base/auxiliary components，并使它们属于一个明确的 publication version；
2. **C2 — version-bound global-column query reorganization**：依据每个组件保留的
   全局 `ColumnIndex` 重组查询，并把 logical state、ordered components、query
   identity、prepared query 与同一 version/binding 一起检查；
3. **C3 — private RowMap-aware multi-component reconstruction**：由非 Cloud 方持有
   私有、版本化的 `RowMap`-aware plan，把多个物理组件/块映射回逻辑输出，明确
   处理 overlap sum、disjoint concatenation 与 implicit zero；
4. **C4 — overlap-scoped canceling masks**：Client A 只在真实 overlap
   contributor group 上产生并加密随机 additive shares，使其和在模明文域中为零；
   Client B 解密并按完整 OutputPlan 合并，但不接收 individual mask plaintexts；
   每个 random operand 绑定到 query/version/plan/component/block scope，并拒绝
   durable-ledger 内复用。

“支持更新”“做输入重排”“客户端重构”“使用 mask”中的任意一个相似词都不等于
覆盖以上精确定义。尤其是矩阵链内部的动态对齐、去重 mask、单矩阵逆置换、一般
secure aggregation 或一般版本号，都只算组成先例。

## 3. 检索协议与范围

### 3.1 来源规则

只用原论文/作者预印本、出版社或会议官方页面、官方代码仓库与规范。检索覆盖：

- arXiv 的 `cs.CR`、`cs.DS`、`cs.DC`；
- IACR Cryptology ePrint；
- ACM/USENIX/IEEE/Elsevier/MDPI 与 DAC 官方页面；
- 已知论文的全文、参考文献边界与作者代码。

没有用博客、聚合摘要或模型回答建立事实。搜索引擎只用于定位一手材料；矩阵中的
事实回到原论文或官方记录核验。

### 3.2 查询族

检索日期为 2026-08-28，主要查询族包括：

- `homomorphic encryption dynamic sparse matrix vector multiplication update`
- `homomorphic encrypted SpMV dynamic mutable sparse matrix update`
- `dynamic homomorphic sparse matrix-vector multiplication`
- `mutable CSSC homomorphic SpMV`
- `version RowMap homomorphic encryption sparse matrix`
- `multi-component reconstruction homomorphic sparse matrix output masking`
- `homomorphic matrix-vector additive shares`
- `sparse matrix FHE output shares`
- `base delta homomorphic sparse matrix query`
- `query reorganization sparse matrix-vector homomorphic`
- `dynamic encrypted graph homomorphic update queries`
- 对 CSSC、Lodia、CipherSkip、2DPP、SparseE、Rhombus、Ferguson/D'Agata、
  ROOM、Bonawitz、Obladi、d-DSE、OblivGNN、GraphGuard 和 CKKS-Auth Tree
  的题名与引用链定向核验。

对 [CipherSkip](https://eprint.iacr.org/2026/297) 与
[Lodia](https://eprint.iacr.org/2025/1425) 的公开全文还定向检查了
`dynamic/update/version/RowMap/reconstruct/mask/component/epoch`。该检查用于辨别
术语语义，不把“某词未出现”单独当作不存在某机制的证明。

## 4. 结论先行

截至检索截止日，在已核验的一手材料中，**没有发现一篇论文或一个系统同时覆盖
C1--C4**。最接近的直接工作分别覆盖不同切面：

- [CSSC](https://arxiv.org/html/2603.04742v1) 给出静态 `VA/CI/RM/CP`、全局列号
  查询重组和单矩阵 `RowMap` 恢复，但作者明确把 evolving sparsity 和避免 full
  recompression 的 incremental update 留作未来工作；
- [CipherSkip](https://eprint.iacr.org/2026/297) 处理结构隐藏的 FHE SpGEMM、
  encrypted indices、链式矩阵乘法和用户端结果重构，但其 “dynamic server-side
  alignment” 是一次链式计算内对加密中间结果的对齐；其 masks 用于 equality、
  deduplication 或 logical reset，不是版本化 CSSC 组件间的随机零和 output shares；
- [Rhombus](https://eprint.iacr.org/2024/1611) 已把 HE MVM 输出用随机减法转换成
  两方 additive shares；[Bonawitz et al.](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)
  已明确给出成对加/减随机向量并在求和中抵消。因此 C4 的原语并不新；候选差异
  只在 private OutputPlan 决定 overlap scope，并与 version/plan/ledger 联合绑定；
- [CKKS-Auth Tree](https://www.mdpi.com/2079-9292/15/12/2517)、
  [Obladi](https://www.usenix.org/conference/osdi18/presentation/crooks) 与动态加密
  数据系统已有 versioned commitments、epoch commit、update/freshness/replay
  处理，但不提供 CSSC SpMV 的全局列号 query path 或 RowMap 多组件重构。

所以，检索结果支持的是一个**窄的系统/协议组合贡献候选**，不是新 HE 原语、
新 masking 原语、首次密文更新或首次 encrypted sparse computation。

## 5. 单篇工作覆盖矩阵

符号：`✓` 为来源明确覆盖；`△` 为只覆盖较宽泛或不同语义的组成概念；`—` 为
不覆盖；`?` 为可公开一手材料不足以核验。最后一列要求 C1--C4 全部成立。

| 一手工作 | C1 mutable/versioned CSSC | C2 version-bound global-column query | C3 private RowMap multi-component reconstruction | C4 overlap-scoped canceling masks | 完整组合碰撞 |
|---|---|---|---|---|---|
| [Gao et al., CSSC 2026](https://arxiv.org/html/2603.04742v1)（[DOI](https://doi.org/10.1016/j.ins.2026.123180)） | —；原文明确为 static pattern，incremental update 是 future work | `△/✓`；静态单矩阵依据全局 `CI` 重组 query，无 version binding | △；单矩阵 `RM` 恢复，不是多个 published components 的私有 plan | —；计算中的 plaintext masks 不是随机 output shares | **否** |
| [Yu et al., Lodia 2025](https://eprint.iacr.org/2025/1425)（[DOI](https://doi.org/10.1145/3719027.3765025)） | —；固定矩阵编码 | —；low-diagonal route，不是 CSSC global-`CI` gather | △；内部矩阵分解/合并不是 private RowMap plan | — | **否** |
| [Mutluergil et al., 2DPP 2026](https://arxiv.org/html/2604.04683v2) | —；静态方阵 | △；有 column permutation preprocessing，但无 CSSC/version binding | △；有单矩阵 row inverse permutation，无 multi-component overlap semantics | — | **否** |
| [Xiong et al., CipherSkip 2026](https://eprint.iacr.org/2026/297)（[DOI](https://doi.org/10.1145/3797905.3807876)） | —；一次 SpGEMM/矩阵链，不是随时间演化的 publication state | △；encrypted index alignment，不是 version-bound CSSC `CI` query | △；用户重构最终矩阵，但没有 RowMap-aware published-component plan | —；mask 是 equality/dedup/reset，不是随机 canceling shares | **否** |
| [Wei et al., SparseE, DAC 2026 官方摘要](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108) | ?；公开摘要未报告 | △；encrypted-index Scatter--Gather--Apply | ?；公开摘要未报告 | ?；公开摘要未报告 | **未发现；全文不可核验** |
| [Ferguson et al. 2025](https://arxiv.org/abs/2503.09184) 与 [D'Agata et al. 2026](https://arxiv.org/abs/2604.11659) | —；静态 SpMSpM | —；公开 sparsity metadata，不是本文 query contract | — | — | **否** |
| [He et al., Rhombus 2024](https://eprint.iacr.org/2024/1611)（[DOI](https://doi.org/10.1145/3658644.3690281)） | —；静态 MVM/PPML | — | △；协议输出 additive shares，但不是 CSSC component/RowMap reconstruction | △；随机 mask 把整个 MVM 输出转成两方 shares，不是 overlap-only 或 ledger-bound | **否** |
| [Schoppmann et al., ROOM 2019](https://eprint.iacr.org/2019/281)（[DOI](https://doi.org/10.1145/3319535.3339816)） | —；静态 MPC sparse data | △；安全 Gather/Scatter 是更一般的私有索引先例 | △；输出可为 additive shares，但无 CSSC RowMap/version plan | —；不是本文的 overlap mask integration | **否** |
| [Bonawitz et al., Secure Aggregation 2017](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)（[DOI](https://doi.org/10.1145/3133956.3133982)） | — | — | — | ✓；成对一次性加/减 masks 在总和中抵消 | **否** |
| [Parbat--Chatterjee FHE DB update](https://doi.org/10.1109/TKDE.2022.3221148)、[d-DSE](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli)、[Obladi](https://www.usenix.org/conference/osdi18/presentation/crooks)、[CKKS-Auth Tree](https://www.mdpi.com/2079-9292/15/12/2517) | △；分别覆盖 encrypted update、动态 state、epoch 或 versioned root | —；不是 CSSC SpMV query | — | — | **否** |
| [OblivGNN](https://www.usenix.org/conference/usenixsecurity24/presentation/xu-zhibo) 与 [GraphGuard](https://www.usenix.org/conference/usenixsecurity24/presentation/wang-songlei) | △；分别覆盖 secure graph update 或 streaming snapshots | —；任务/密码原语不同 | — | — | **否** |
| [Dynamic-CSR](https://doi.org/10.1007/978-3-319-43659-3_25)、[LSM-tree](https://doi.org/10.1007/s002360050048)、[Morpheus](https://arxiv.org/abs/2209.06478) | △；plaintext update/slack/base-delta/merge/format switching | — | △；一般 component merge，不是 private RowMap output plan | — | **否** |

## 6. 组成先例与可守差异

### 6.1 C1 不是“一般动态更新”的新颖点

Plaintext dynamic sparse formats 已覆盖 slack、overflow、局部增长和格式切换；LSM
已覆盖 base/delta components 与 merge；FHE databases、dynamic SSE、Obladi、
OblivGNN 和 GraphGuard 已覆盖不同形式的 encrypted update、epoch、streaming state
或 secure graph update。可守差异只能是：**这些 state invariants 被具体绑定到
CSSC components 及其 query/reconstruction semantics**。

### 6.2 C2 的静态 substrate 完全归 CSSC

CSSC 原文已经规定 Client B 根据 `ColumnIndex` 重组向量。2DPP 也有输入 column
permutation 与输出 row inverse permutation。Route A 不能把 query reorganization、
row/column permutation 或 global indices 单独作为贡献；候选差异是 query metadata
与逻辑 state、ordered components、version 和 prepared-query identity 的联合一致性。

### 6.3 C3 必须强调“多组件 + 私有 plan + 逻辑坐标语义”

CSSC 已有单矩阵 `RowMap`；CipherSkip 已有用户端结果重构；ROOM、Rhombus 与其他
安全计算已有 additive-share output。Route A 的窄差异是一个版本化私有 plan 同时
规定多个 independently published physical components/blocks 到逻辑坐标的映射，
并区分 overlap sum、disjoint concatenation 与 implicit zero。没有 functional tests
与 proposition evidence 时，这仍只是设计对象而不是已成立结论。

### 6.4 C4 是应用特定集成，不是新密码学原语

Bonawitz et al. 的 Lemma 6.1 和 one-time-pad intuition 已给出成对随机向量的加减
抵消；Rhombus 的 HE-to-additive-sharing path 已给出 MVM output masking。Route A
只能把差异放在 `OutputPlan`-derived overlap scope、五元组 reservation identity、
Client A sampling/encryption、Client B 不持有 individual mask plaintexts、原子
durable ledger 和 single-consumption binding。它目前不建立 simulation security、
跨设备防复用、rollback resistance 或完整 topology hiding。

## 7. 裁决与论文措辞

### 7.1 PASS 的精确含义

**PASS** 表示：截至 2026-08-28，在上述一手来源与查询范围内，没有找到一个
single prior system/paper 同时覆盖 C1--C4；因此 Route A 可以继续把下述内容作为
**待正确性与实现证据支持的 combined systems/protocol contribution**：

> We present a version-bound protocol for mutable CSSC-based homomorphic SpMV
> that jointly binds logical matrix state, global-column query
> reorganization, private `RowMap`-aware multi-component reconstruction, and
> overlap-scoped canceling masks; we establish its functional correctness properties and
> characterize bounded-scale costs in a reproducible OpenFHE implementation,
> without claiming performance superiority.

Related Work 可以写：

> Prior work separately covers static encrypted sparse linear algebra,
> dynamically updated encrypted data, private index routing or output sharing,
> and canceling masks. In the primary sources examined through 2026-08-28, we
> did not find a single system that combines these mechanisms with the same
> mutable-CSSC version and reconstruction semantics.

这两句都避免了 `first`，并把“未发现”绑定到公开的检索范围与日期。

### 7.2 仍为 HOLD 的表述

以下表述仍然 **HOLD/禁止**：

- `the first/only dynamic encrypted SpMV` 或中文等价；
- 首次使用 encrypted indices、global-column query reorganization、versioned
  commitments、epoch publication、multi-component storage、output shares、
  canceling/zero-sum masks 或 durable nonce/mask tracking；
- `novel cryptographic primitive`、`secure aggregation protocol`、
  `simulation-secure`、完整结构隐藏或优于既有方法的安全性；
- 由文献空白直接推出 correctness、practicality、performance superiority 或
  publishability。

如必须使用 “to our knowledge, the first”，至少还需系统性数据库与专利检索、
前向/后向引用链、作者/标题变体和非英语来源复核，并公开检索式与排除理由。

## 8. 局限与重开条件

1. 这是文献工程审计，不是法律 novelty opinion、专利 freedom-to-operate 分析或
   数学上的 absence proof。
2. 搜索以公开可索引的英语材料为主；未穷尽付费数据库、学位论文、专利、非英语
   文献、未公开投稿和 2026-08-28 之后的新版本。
3. SparseE 截止当日只有 DAC 官方题名、作者和摘要可核验；没有公开全文、DOI 或
   官方实现。本裁决不能把“摘要未写”升级为“全文一定没有”。其全文若在 formal
   dispatch 前公开，则 dispatch 暂停并重开本 gate；若在 immutable formal runs 已
   dispatch 后公开，不因该事件单独取消这些 runs，但不得再 dispatch 尚未发出的
   shards，且 aggregate acceptance、结果解释、论文主张和投稿暂停，直至重审。
   投稿前必须再做一次 availability check。
4. CSSC 原文对 sparsity-public 与 Cloud 不见 indices/RowMap 的文字存在张力；
   Route A 的 ACL/leakage contract 必须归属于本项目，不能冒充 CSSC 原文结论。
5. 本审计只判断 prior-art overlap，不验证仓库是否正确实现 P1--P4，也不把测试、
   CI 或外部模型评审当作论文证据。
6. 若 Route A 后续移除 CSSC-specific、version-bound、private RowMap-aware、
   multi-component 或 overlap-scoped 中任何限定词，claim 会明显变宽，必须重新
   检索；若加入安全、性能或全局 first claim，也必须重新开 gate。

## 9. 主要一手来源索引

### 直接 encrypted sparse linear algebra

- Gao et al., CSSC: [arXiv full text](https://arxiv.org/html/2603.04742v1),
  [publisher DOI](https://doi.org/10.1016/j.ins.2026.123180).
- Yu et al., Lodia: [IACR ePrint](https://eprint.iacr.org/2025/1425),
  [ACM DOI](https://doi.org/10.1145/3719027.3765025).
- Xiong et al., CipherSkip: [IACR ePrint](https://eprint.iacr.org/2026/297),
  [ACM DOI](https://doi.org/10.1145/3797905.3807876).
- Mutluergil et al., 2DPP: [arXiv v2](https://arxiv.org/html/2604.04683v2).
- Wei et al., SparseE: [DAC 2026 official program](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108).
- Ferguson et al.: [arXiv](https://arxiv.org/abs/2503.09184),
  [ACM DOI](https://doi.org/10.1145/3721146.3721948).
- D'Agata et al.: [arXiv](https://arxiv.org/abs/2604.11659),
  [ACM DOI](https://doi.org/10.1145/3805621.3807642).

### 私有 routing、output shares 与 canceling masks

- He et al., Rhombus: [IACR ePrint](https://eprint.iacr.org/2024/1611),
  [ACM DOI](https://doi.org/10.1145/3658644.3690281).
- Schoppmann et al., ROOM: [IACR ePrint](https://eprint.iacr.org/2019/281),
  [ACM DOI](https://doi.org/10.1145/3319535.3339816).
- Bonawitz et al.: [conference PDF](https://acmccs.github.io/papers/p1175-bonawitzA.pdf),
  [ACM DOI](https://doi.org/10.1145/3133956.3133982).

### 动态/版本化加密数据先例

- Parbat and Chatterjee: [IEEE DOI](https://doi.org/10.1109/TKDE.2022.3221148).
- Crooks et al., Obladi: [USENIX official page](https://www.usenix.org/conference/osdi18/presentation/crooks).
- Liu et al., d-DSE: [USENIX official page](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli).
- Chen et al., CKKS-Auth Tree: [publisher full text](https://www.mdpi.com/2079-9292/15/12/2517),
  [DOI](https://doi.org/10.3390/electronics15122517).
- Xu et al., OblivGNN: [USENIX official page](https://www.usenix.org/conference/usenixsecurity24/presentation/xu-zhibo).
- Wang et al., GraphGuard: [USENIX official page](https://www.usenix.org/conference/usenixsecurity24/presentation/wang-songlei).

本文件的 PASS 只对第 2 节四条件的交集成立；每个组成概念的 prior art 均应在最终
Related Work 中明确归属。

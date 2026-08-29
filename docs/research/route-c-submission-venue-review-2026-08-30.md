# Route C 投稿 venue 评审（截至 2026-08-30）

## 结论先行

这篇稿件现在可以作为**方法／协议与证据边界论文**准备投稿，但不能包装成性能论文、完整安全性证明或成功完成的实证研究。可守住的核心贡献是：

1. version-bound mutable CSSC protocol；
2. 可审查的 functional propositions 及其确定性验证；
3. fail-closed 的复现与证据边界；
4. 按预注册规则停止的 qualification，以及“哪些结论因此不能成立”。

按当前稿件形态、官方范围、截止时间和费用综合排序：

1. **Cyber Security and Applications（CSA）加密数据安全计算专刊**：主题最直接，建议作为默认路线；
2. **IACR Communications in Cryptology（CiC）**：学术共同体和出版模式最好，但需要更强地证明“正确且原创的方法贡献”；
3. **PeerJ Computer Science**：对方法学健全性和非正结果最友好，但费用较高、密码学受众较分散；
4. **Journal of Cryptographic Engineering（JCEN）**：无固定截止且可零 APC，是保守备选；其硬件／嵌入式倾向使 scope 风险高于前三项。

这里的“排序”不是允许同时投稿的序列。所有正式 venue 都禁止一稿多投；应当先选一个。若选 CSA，可先在 FHE.org 2027 的 **2026-11-01 23:59 AoE（北京时间 2026-11-02 19:59）** 截止前提交 2–4 页摘要／海报取得同行反馈，再在 2026-12-01 前完成期刊稿。

## 判断边界

- 本评审只使用会议、期刊或出版社的官方 CFP、作者指南、定价和政策页面；核查日为 **2026-08-30（Asia/Shanghai, UTC+8）**。
- “无正式比较性能结果”不等于“没有结果”。稿件必须把 functional propositions、版本绑定、失败闭合机制及其验证作为主要结果；stopped qualification 只能作为受预注册约束的证据边界，不能冒充速度、扩展性或安全性结论。
- 截止页面若只给日期、不写时区，本评审明确记为“时区未公布”，不擅自按 AoE 换算。
- 下文“最小改稿量”是基于当前约 6,357 字、约 22 页稿件的工作估计，不是 venue 官方承诺，也不包含同行评审后的返修时间。

## 总表

| 排名 | Venue | 截至核查日的下一机会 | 篇幅与模板 | OA／费用 | 当前适配判断 |
|---|---|---|---|---|---|
| 1 | CSA 专刊 *Secure Computation and In-depth Utilization over Encrypted Data* | **2026-12-01**；官方页未给时区 | 官方指南未给通用页数上限；摘要不超过 350 字；Word 或 Elsevier LaTeX | 全 OA；当前作者指南列示 APC **USD 0**（税费栏亦为 0） | 主题最精确，但仅计划录用 8–12 篇，必须把功能性结果写成完整原创研究 |
| 2 | IACR Communications in Cryptology | 官网年度表列 **2026-10-26**；CFP 的 cutoff convention 为 23:59 AoE，即北京时间次日 19:59，但 Issue 4 页面仍须复核 | Regular paper 20 页（参考文献不计）；当前 CFP 指定 `iacrcc` LaTeX，匿名 PDF | Diamond OA、CC BY 4.0；作者和读者均无费用 | practitioner／SoK 与现实密码工程范围有利；但不能只交“执行计划” |
| 3 | PeerJ Computer Science | 滚动投稿，无固定 deadline | 无常规页数上限；超过 40 个最终排版页有额外费用；DOCX 优先，也收 LaTeX | 全 OA；Research Article 当前 APC **USD 2,155**，另有机构、会员或减免路径 | 审正确性而非影响力，明确接收 null findings；但 stopped qualification 本身并非 null result |
| 4 | Journal of Cryptographic Engineering | 普通稿滚动投稿，无固定 deadline | 官方普通稿指南未列页数上限；摘要 150–250 字；Springer Nature LaTeX 推荐，也收 Word | Hybrid；订阅路线无 APC，OA 可选费用当前约 USD 3,490／EUR 2,890／GBP 2,590，税另计 | 密码工程相关且零 APC 路线可行；硬件／嵌入式倾向与验证要求构成较大风险 |

## 1. Cyber Security and Applications 专刊——默认首选

### 为什么匹配

专刊官方主题直接覆盖 FHE/PHE、加密数据查询与分析、secure data analytics、可验证计算、FHE/MPC 系统架构与加速。这比泛安全会议更容易让编辑理解“动态 CSSC 结构为什么需要版本绑定、可复现状态转换和 fail-closed evidence boundary”。专刊明确接受 open call，不要求来自 DSPP 2026 会议。

当前稿件应投 **Research Article**，而不是以“短报”规避结果要求。主张应重写为：协议解决了什么可变状态与版本一致性问题；functional propositions 如何限定合法行为；哪些自动化检查构成可复核证据；预注册 qualification 为什么停止，以及停止后禁止推出哪些结论。

官方来源：

- [专刊 CFP：主题、投稿入口和日期](https://www.keaipublishing.com/en/journals/cyber-security-and-applications/call-for-papers/special-issue-on-secure-computation-and-in-depth-utilization-over-encrypted-data/)
- [CSA 期刊范围](https://www.keaipublishing.com/en/journals/cyber-security-and-applications/)
- [作者指南：稿型、格式、OA、数据和 AI 政策](https://www.keaipublishing.com/en/journals/cyber-security-and-applications/guide-for-authors/)

### Deadline、格式与费用

- Submission Due：**2026-12-01**。官方 CFP 没有写时间或时区；因此不能把它换算成一个经验证的北京时间。建议内部截止设为 **2026-11-29 18:00（北京时间）**，临投前再在 Editorial Manager 和 guest editor 页面核实。
- 投稿时在 Editorial Manager 选择 **`VSI: SCUED-DSPP2026`**。
- 官方作者指南当前未列 Research Article 的页数／字数上限；摘要不超过 350 字，3–6 个关键词。可交 `.doc/.docx`，LaTeX 建议使用 Elsevier 模板，录用流程需要可编辑源文件。
- 当前官方费用表列示所有文章 APC 为 **USD 0**。这仍应在提交页和录用协议中复核，尤其是税费、超长或未来政策变化。
- 数据政策鼓励公开数据、代码、协议并给 DOI，但当前指南没有单独的 artifact badge 流程。至少应冻结确切 commit/tag；最好在投稿前做 Zenodo 归档 DOI。

### 最小改稿量与风险

估计 **4–7 个专注工作日**：调整题目和摘要；把 propositions 及验证提升为 Results；把停止条件写成 preregistered evidence-boundary result；加入 Data/Code Availability 与 AI-use statement；删除所有暗示性能领先、端到端安全或一般化正确性的句子。

主要风险是专刊只计划录用 **8–12 篇**，并按相关性、贡献重要性、技术质量和表达质量评审。官方日期栏还存在“Final Notification 2027-05-01”早于“Editorial Acceptance Deadline 2027-12-31”的内部不一致，说明不能据此承诺决定或出版时间。当前稿件若没有把 functional propositions 形成一个完整、可检验的原创技术结果，仍可能被认为证据不足。

## 2. IACR Communications in Cryptology——高质量、零费用的密码学首选

### 为什么匹配

CiC 是 IACR 的 diamond open-access 期刊，范围包括密码学的应用、实现和现实问题。官方 FAQ 明确接受 SoK 和 practitioner papers，并说明其贡献类型比 IACR 旗舰／领域会议更广，评审重点是工作是否正确、原创且与密码学相关，而不是是否能挤进固定录用名额。这与“可执行协议 + 功能命题 + 可复核证据边界”的定位相容。

但“相容”不代表可以只提交框架。最安全的文章类型仍是 regular research/practitioner paper：把协议与 functional propositions 作为正贡献，把 stopped qualification 限定为不支持性能主张的事实。不要把它写成形式安全定理，也不要声称 immutable artifact 自动等于复现成功。

官方来源：

- [CiC 首页：2026 年各期时间表与 diamond OA](https://cic.iacr.org/)
- [Call for Papers：范围、篇幅、匿名和补充材料](https://cic.iacr.org/page/callforpapers)
- [FAQ：SoK／practitioner papers、评审哲学和费用](https://cic.iacr.org/page/faq)

### Deadline、格式与费用

- 官网 2026 年度表列 Issue 4 submission date 为 **2026-10-26**；官方 CFP 写明 submission cutoff convention 是 **23:59 Anywhere on Earth (AoE)**，换算为北京时间为 **2026-10-27 19:59**。但是截至核查日，CFP 日期卡仍是上一轮而不是独立 Issue 4 页面，因此临投前仍要确认 Issue 4 继承同一 cutoff convention。
- Regular paper 上限 20 页，参考文献不计；超过 20 页应按 long paper 处理，且可能顺延评审轮次。当前 CiC CFP 指定 IACR `iacrcc` LaTeX 类、`version=submission`，匿名 PDF 投稿；最终稿也需 LaTeX 源文件。[IACR 官方 LaTeX 仓库](https://github.com/IACR/latex)正在维护新模板体系，故应以 Issue 4 正式页面临投时给出的类名为准，不能提前锁死旧模板。
- Diamond OA、CC BY 4.0，不收作者 APC，也无强制参会成本。
- 官方鼓励在可能时提供支撑实验的代码和数据；附录／补充材料可随文公开。当前工作应给不可变 release、环境和验证入口，避免只指向可变分支。

### 最小改稿量与风险

估计 **5–8 个专注工作日**：由 Markdown/Word 转成 `iacrcc`；压到 20 页或有意识地选 long paper；匿名化；为每个 proposition 给定义、前提、论证／测试对应关系；加限制、artifact 和生成式 AI 披露。

主要风险是密码学评审会追问“原创技术推进究竟是什么”。没有形式安全证明和正式性能结果并非自动拒稿，但文章必须证明协议及其验证边界本身足够新、足够正确。另一个实际风险是 2026-10-26 比 CSA 早，而 CiC 的通知日在 CSA 截止之后；两者不能同时投稿，所以选择 CiC 就意味着本轮不能把 CSA 当作等待结果后的无缝后备。

## 3. PeerJ Computer Science——方法学／非正结果友好的现实路线

### 为什么匹配

PeerJ Computer Science 覆盖全部计算机科学。其官方 editorial criteria 明确按科学和方法学健全性评审，而不是按预期影响力或读者规模筛选，并明确容纳 null findings 与有合理价值的复现研究。这使“证据到哪里为止”可以被诚实讨论。

不过，本项目的 stopped qualification 是“没有获得可采信性能证据”，不是一个已经完成、统计定义良好的零结果。文章仍须以 functional propositions、协议语义和可重复的确定性验证作为主要结果，不能把“实验停止”单独当作可发表发现。投稿类型应为 **Research Article**；当前内容不属于 opinion/commentary。

官方来源：

- [PeerJ Computer Science 范围与稿型](https://peerj.com/about/aims-and-scope/cs)
- [Computer Science editorial criteria](https://peerj.com/about/editorial-criteria/cs)
- [作者指南：格式、软件／数据归档](https://peerj.com/about/author-instructions/cs)
- [官方定价](https://peerj.com/pricing/)

### Deadline、格式与费用

- 滚动投稿，没有固定日期或时区。
- 官方没有普通 Research Article 的硬页数上限；最终排版超过 40 页会产生超页费用。DOCX 是偏好格式，也接受 LaTeX；初稿应单栏并带行号。摘要上限 500 字。
- 全 OA、CC BY。当前定价页列 PeerJ Computer Science Research Article APC 为 **USD 2,155**（当地税费可能另计）；机构协议、会员和减免可能改变实付金额，应在投稿账号内复核。
- 对软件／数据的要求比前两项更明确：GitHub 代码应在 Zenodo 等 DOI 仓库冻结确切版本，正文给出代码、数据和复现实验入口。仅给活动分支链接不够。
- 同行评审历史公开，方法与边界表述会长期可见，反而有利于证明作者没有把未完成实验包装成正结果。

### 最小改稿量与风险

估计 **5–9 个专注工作日**：按 Background–Methodology–Results–Discussion–Conclusions 重排；把 proposition 论证和验证映射写全；制作 Zenodo DOI；补全 Data/Code Availability、Funding、Competing Interests 和 AI-use 等声明。

主要风险是密码学专业受众较弱、APC 较高，以及“方法学友好”仍不等于接受未完成的工作。若编辑认为 protocol 只是工程脚手架、没有可独立审查的研究问题与结果，会在 soundness 评审前失败。

## 4. Journal of Cryptographic Engineering——保守备选

### 为什么保留

JCEN 的官方范围包括密码工程中的算法、技术、工具、实现与应用，也列出高效软件架构、安全评估和形式方法。它允许普通稿滚动投稿；选择传统订阅出版无需 APC。因此，在前三个窗口错过或不适用时，它是一个不会被固定 deadline 卡死的正式备选。

适配点同时也是风险：该刊明显重视硬件、嵌入式实现和传统密码工程验证。Route C 必须突出“版本化可变数据结构对密文计算管线的工程正确性约束”和工具化验证，不能只谈通用 reproducibility governance。

官方来源：

- [Aims and scope](https://link.springer.com/journal/13389/aims-and-scope)
- [Submission guidelines](https://link.springer.com/journal/13389/submission-guidelines)
- [How to publish／OA 费用](https://link.springer.com/journal/13389/how-to-publish-with-us)
- [Collections：用于核对而非误投专刊](https://link.springer.com/journal/13389/collections)

### Deadline、格式与费用

- 普通稿滚动投稿，没有固定 deadline 或时区。官网当前列出的 2026-09-30 “Security Proofs for Embedded Systems” collection 面向特定 PROOFS 工作，**不应**把本稿硬投进去。
- 普通稿指南当前未给硬页数上限；摘要 150–250 字、4–6 个关键词。Springer Nature LaTeX 模板为推荐路径，也接受 Word。
- Hybrid：传统订阅路线无 APC；可选 OA 的当前标价约为 USD 3,490／EUR 2,890／GBP 2,590，税费可能另计，最终金额以录用时系统为准。
- 原创研究需 Data Availability Statement；公开代码／数据仓库和补充材料受到鼓励。应提交 immutable release，并把可执行验证与未执行 qualification 区分开。

### 最小改稿量与风险

估计 **4–7 个专注工作日**：转 Springer 模板；收紧摘要；加入 declarations 和 Data Availability；强化 cryptographic engineering 问题、functional verification 和可实现性；弱化一般方法学宣言。

最大风险是 scope 和验证深度：没有硬件贡献、正式安全证明或比较性能时，稿件可能显得处在该刊边缘。因此它是保守的“有时间继续强化后再投”备选，不是最容易录用的捷径。

## 可并行取得反馈、但不能替代正式论文的 FHE.org 2027

[FHE.org 2027 官方 Call for Presentations](https://fhe.org/conferences/conference-2027/call-for-presentations)及其[官方 submission instructions](https://fhe.org/conferences/conference-2027/submissions)给出：2–4 页 extended abstract（参考文献不计）、talk 或 poster、单盲；截止 **2026-11-01 23:59 AoE**，即北京时间 **2026-11-02 19:59**。会议在 2027-04-04 于 Seattle 线下举行，至少一名作者需要注册和报告。

它的受众正好关心 FHE 系统、benchmarking、工程可部署性以及“系统在哪里卡住”。更重要的是，官方说明不出版 proceedings，因而适合在 CSA 截止前获得反馈，也不会把 2–4 页摘要伪装成最终论文。建议摘要只讲协议、证据边界与预注册停止，不给任何未经支持的性能结论。临近投稿仍须核对注册费、差旅、非归档声明和后续期刊的 prior-publication 政策。

## 明确不建议当前直接投的方向

- **PoPETs 2027**：其[官方 CFP](https://petsymposium.org/cfp27.php)和[作者指南](https://petsymposium.org/authors-2027.php)要求论文在首页及全文建立真实世界隐私联系，并把稿件视为完整、完成的工作；2027 模板主文投稿上限 12 页。下一可实际准备的轮次是 **2026-11-30 23:59:59 AoE**（北京时间 2026-12-01 19:59:59）。当前 22 页稿件既缺正式 privacy/security 结果，又需大幅压缩，属于重大重定位后的 stretch target，不是现实首投。
- **JOSS**：其[投稿要求](https://joss.readthedocs.io/en/latest/submitting.html)和[评审标准](https://joss.readthedocs.io/en/latest/review_criteria.html)面向成熟的研究软件，要求公开开发历史、研究影响、社区／外部采用证据及完整软件发布。当前项目没有足够长的公开开发与外部使用历史，而且 JOSS 的短 software paper 不能承载本稿的方法／证据边界论证；现在硬投有 desk-reject 风险。
- 顶级 security/privacy 主会不应作为本轮目标：当前明确没有完整安全定理、攻击者模型下的证明或正式比较评估。等这些证据真正形成后再重新做 venue scan，不能先选会再反向放大主张。

## 建议的投稿决策与最小行动集

### 推荐路径 A：范围匹配优先

1. 2026-09 上旬完成 propositions、claim-to-evidence 表和不可变 artifact；
2. 2026-10 下旬形成 2–4 页 FHE.org 摘要，但不把它算成论文发表；
3. 吸收同行反馈后，在内部截止 2026-11-29 前投 CSA 专刊。

### 推荐路径 B：密码学共同体与 diamond OA 优先

1. 立即按 `iacrcc` 20 页 regular paper 设计稿件；
2. 在 2026-10-20 前完成匿名稿、artifact 和所有声明；
3. 核实 Issue 4 正式 CFP 的具体时区后，于官方 2026-10-26 日期前投稿。

### 四个 venue 共用的最低门槛

- 一张逐项 claim → proposition/test/artifact → limitation 的证据矩阵；
- 一个带 DOI 或至少 immutable tag/commit 的可复核 release，记录环境和命令；
- 清楚分开“功能一致性通过”“性能 qualification 停止”“从未主张的安全性质”；
- 摘要、结论和图表中零处使用“faster / scalable / secure / reproducible”而没有对应证据或限定词；
- 按目标 venue 的 AI-assisted writing policy 披露工具使用，作者对全部文本、公式、代码和引用负责。

## 临近投稿必须重新核实

1. CiC Issue 4 的正式 CFP、投稿入口、精确时刻／时区和当期 `iacrcc` 版本；
2. CSA Editorial Manager 是否已开放 `VSI: SCUED-DSPP2026`、2026-12-01 的时区、专刊内部日期矛盾，以及 USD 0 APC 是否仍有效；
3. PeerJ 当日 APC、机构协议／waiver、40 页计费规则和软件 DOI 要求；
4. JCEN 当日模板、篇幅、OA 价格和普通稿 scope；
5. 所有 venue 的生成式 AI 声明文本、双重投稿／预印本政策、作者资格、利益冲突和数据许可；
6. FHE.org 的注册费、现场报告责任以及最终期刊对该非归档摘要的 prior-publication 判断。

## 最终判断

这篇稿件不是“等跑出漂亮性能就能投”的半成品；它最有价值也最可信的形式，是一篇说明协议如何被版本绑定、哪些功能性质确实被验证、证据链怎样 fail closed、以及 qualification 为什么按预注册规则停止的方法论文。按这个边界，CSA、CiC 与 PeerJ 都是现实选择，但都要求把 functional propositions 写成真正的研究结果。若现在仍只有框架叙述而没有可审查的命题—验证对应关系，则上述四项都不应立即投稿。

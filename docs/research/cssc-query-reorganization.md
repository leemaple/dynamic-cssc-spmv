# CSSC query reorganization：一手材料窄范围核验

核验日期：2026-08-22（Asia/Shanghai）  
核验对象：Yang Gao 等，*Efficient Privacy-Preserving Sparse Matrix-Vector Multiplication Using Homomorphic Encryption*，arXiv:2603.04742v1 / *Information Sciences* 739 (2026) 123180。  
范围：只核验 CSSC 的 `ColumnIndex`、Client A / Client B / Cloud 分工、Algorithm 1--3 的 query reorganization、query ciphertext 数量、全局列号与 slot 域、返回结果及 `RowMap` 语义。

## 1. 来源与证据边界

本报告只使用作者提交或出版方记录：

- [arXiv 作者记录与版本信息](https://arxiv.org/abs/2603.04742)；
- [arXiv 官方 PDF](https://arxiv.org/pdf/2603.04742)；
- [arXiv 官方 TeX source](https://arxiv.org/e-print/2603.04742)；
- [出版方 DOI 记录](https://doi.org/10.1016/j.ins.2026.123180)。

本地复核的 arXiv v1 PDF SHA-256 为 `ee4d1b5f15be58e8c4815bc595a58b486ac56c05529da973b05b01a5c3bcd485`，TeX source tarball SHA-256 为 `125d878832522d76df6516cf749fe7c1ba94604682bc25363fa4e0dfe37e6403`。下文页码指 PDF 印刷页码（与 PDF 页序一致）。

PDF、TeX source 和 arXiv 记录都没有给出作者代码仓库 URL。对 GitHub 以论文全名、`Compressed Sparse Sorted Column`、`generateChunk`、`reorgVector`、`ct_reorg_vector` 做定向 repository/code 搜索，也没有定位到作者公开实现；命中的只是论文索引或 feed 镜像。因此本报告没有任何“作者代码已复现”或“实现行为与伪代码一致”的主张。未找到公开仓库不等于作者从未发布代码。

本地的 `2025-1935_Fully_Homomorphic_Encryption_for_Matrix_Arithmetic.pdf` 是 Gentry--Lee 的另一篇矩阵算术 FHE 论文，不是 CSSC 来源，未被用于本报告的技术结论。

## 2. 结论先行

| 问题 | 一手材料结论 | 证据强度 |
|---|---|---|
| `ColumnIndex` 是什么 | 每个非零值在**原矩阵中的全局原始列号**；chunk padding 用 `-1` | 直接，CSSC 定义 p.14；Algorithm 2 p.18；Algorithm 5 pp.41--43 |
| 谁得到 `ColumnIndex` | Algorithm 1 的主路径是 Client A 以明文发给 Client B；Client B 据此重组查询；Cloud 只接收两侧 ciphertext | 直接但原文有冲突，§3.3 pp.9--10；Algorithm 1 p.16；Figure 3 p.15 |
| query ciphertext 数量 | 每个 CSSC value chunk 对应一个重组向量和一个 query ciphertext；Cloud 按相同 chunk 下标一一相乘 | 直接，Algorithms 1、3 pp.16, 19 |
| 全局列号能否超过 slot 数 | **能。** `ColumnIndex` 的地址域是 `[0, matrix.cols)`，不是 slot 域；只有重组后的 chunk 长度受 slot 容量约束 | 直接定义 + 必然推论，pp.14, 18--19, 26, 39--40 |
| 返回结果与 `RowMap` | 单次 Algorithm 1 在 Cloud 端先聚合成一个 `ct_res`；解密后仍按排序后的物理行顺序，随后以 `Res[RM[idx]] = mid_res[idx]` 恢复原逻辑行序 | 直接，Algorithm 1 p.16；CSSC 定义 p.14 |
| 动态版本、多个 component、OutputPlan、零和盲化 | 原论文没有定义；论文明确把 evolving sparsity / incremental update 列为未来工作 | 直接，pp.34--35；因此这些属于本项目扩展 |

## 3. `ColumnIndex` 的精确语义

CSSC 被定义为 `(VA, CI, RM, CP)`。其中 `CI` 保存与每个非零值对应的“original column index”，而 `RM` 保存排序后每行对应的原始行号。[PDF p.14](https://arxiv.org/pdf/2603.04742#page=14)

Appendix B 的 Algorithm 5 再次把该语义写成赋值：在遍历排序后的行时，直接执行 `CI[w] <- CIcsr[k] /* original column index in M */`。也就是说，CSSC 的左对齐“列”表示每行第几个非零项；它不是原矩阵的列分块，而槽内 `CI` 仍指向原矩阵列域。[PDF pp.41--43，尤其 Algorithm 5 lines 11--19](https://arxiv.org/pdf/2603.04742#page=41)

Algorithm 2 将连续的 CSSC 左对齐列组合成矩形 chunk，同时抽取相同范围的 `Value` 与 `ColumnIndex`；矩形 padding 写成 `Value=0, ColumnIndex=-1`。[PDF p.18，Algorithm 2 lines 10--16](https://arxiv.org/pdf/2603.04742#page=18)

因此一个 chunk 的最小正确数据模型是两条逐槽对齐的数组：

```text
value_chunk[q][lane]
global_column_index[q][lane] in {-1} union [0, matrix.cols)
```

`start_column` / `width` 可以描述 chunk 覆盖的 **CSSC rank-columns**，但不能替代逐槽的全局 `ColumnIndex`，也不能推出该 chunk 对应原矩阵中的连续列区间。

## 4. Client A / Client B / Cloud 与 query reorganization

### 4.1 原文主路径

系统模型规定：Client A 拥有稀疏矩阵并压缩、加密后传给 Cloud；Client B 拥有 dense vector，从 Client A 得到列号后重组、加密并传给 Cloud；Cloud 做乘法、旋转与明文常量乘并返回加密结果。[PDF p.9，§3.2](https://arxiv.org/pdf/2603.04742#page=9)

Algorithm 1 把消息流写得更具体：[PDF p.16](https://arxiv.org/pdf/2603.04742#page=16)

1. Client A 生成 chunked `value`, `column_index`, `row_map`, `param`；
2. Client A 加密 `value` 发给 Cloud，并把明文 `column_index` 发给 Client B（lines 1--4）；
3. Client B 运行 Algorithm 3，得到 `reorg_vector`，加密后发给 Cloud（lines 5--7）；
4. Cloud 对每个下标 `i` 计算 `ct_value[i] * ct_reorg_vector[i]`（lines 8--11）。

Algorithm 3 对每个 chunk 的 index list 独立生成一个 `one_vec`。其逐槽语义是：[PDF p.19，Algorithm 3](https://arxiv.org/pdf/2603.04742#page=19)

```text
reorg[q][lane] = 0                         if CI[q][lane] == -1
reorg[q][lane] = query[CI[q][lane]]        otherwise
```

Figure 5 也明确写为 `ReorganizedResult[k] = Vector[ColumnIndex[k]]`。索引发生在 Client B 的明文 dense vector 上，随后才把长度受限的 `reorg[q]` 编码进 ciphertext；Cloud 不执行全局随机访问。

### 4.2 每个 CSSC chunk 一个 query ciphertext

Algorithm 3 的输出是“List of permuted vectors”；外层循环每处理一个 `col_idx`（一个 chunk 的 `ColumnIndex`）就 append 一个 `one_vec`。Algorithm 1 随后把 `ct_value[i]` 与 `ct_reorg_vector[i]` 按相同 `i` 一一相乘。因此，对一次 Algorithm 1 调用：

```text
number of reorganized query vectors
= number of query ciphertexts uploaded by Client B
= number of CSSC value ciphertext chunks
```

这不是“整个查询只发一个 ciphertext”，也不是 `ceil(matrix.cols / effective_slots)` 个连续列块。论文的 Cloud 复杂度表同样以 `n_ct` 个对应 ciphertext pair 计 `n_ct` 次 HE-Mult。[PDF p.23，Table 3 与正文](https://arxiv.org/pdf/2603.04742#page=23)

原论文讨论的是一次静态 SpMV 调用，没有 query ID、matrix version、metadata cache 或重复查询协议。因此“同一版本的 `ColumnIndex` 只同步一次”是合理的动态系统设计，但不是原文已经证明的通信语义。

## 5. 全局列号与 slot / `effective_slots` 是两个地址域

设原矩阵为 `r x c`，则有效 `ColumnIndex` 是原始列号，取值域为 `[0,c)`；设一个 ciphertext 实际允许本项目使用 `S_eff` 个槽，则一个重组 chunk 只要求长度不超过 `S_eff`。原算法没有 `CI mod S_eff`，也没有先按 `[b*S_eff,(b+1)*S_eff)` 连续列块切分查询。

论文自身给出三层交叉证据：

- `CI` 明确定义为原矩阵列号，Algorithm 3 在明文查询上执行 `v[idx]`，[pp.14, 19](https://arxiv.org/pdf/2603.04742#page=14)；
- 处理超大矩阵时，论文沿**行维**做 horizontal partition，以限制 chunk 高度，而不是把全局列号约化到 slot 域，[p.26，§4.7](https://arxiv.org/pdf/2603.04742#page=26)；
- 所有实验使用 `N=8192`、8192 batching slots，但 Table A.9 包含 `stat96v5` 的 75,779 列、`stat96v1` 的 197,472 列，以及 `EternityII_E` 的 262,144 列，[p.26 参数](https://arxiv.org/pdf/2603.04742#page=26)，[pp.39--40，Table A.9](https://arxiv.org/pdf/2603.04742#page=39)。

所以，全局列号超过 8191（以及本项目单 batching row 的 `effective_slots=4096`）在协议数据模型上是合法且必须支持的。更准确地说，论文的输入域允许 `c > slots`；由于未发布作者数据处理代码，本报告不声称已从每个实验矩阵中复算其 `max(CI)`。

任何 `query[CI % effective_slots]`、把 `CI` 当 lane 编号、或仅按 `ceil(c / S_eff)` 估算 query ciphertext 的实现，都会改变 Algorithm 3 的函数语义。

## 6. 返回结果与 `RowMap`

CSSC 首先按每行非零数降序重排行；`RM[p]` 是排序后物理行 `p` 对应的原矩阵行号。[PDF p.14](https://arxiv.org/pdf/2603.04742#page=14)，[Appendix B / Algorithm 5 pp.41--43](https://arxiv.org/pdf/2603.04742#page=41)

在单次 Algorithm 1 中，Cloud 不是把每个 chunk product 分别返回给客户端，而是调用 Algorithm 4 先做 chunk 内归约，再以 mask 清除无效槽并跨 chunk 相加，得到一个 `ct_res`。[Algorithm 1 p.16](https://arxiv.org/pdf/2603.04742#page=16)，[Algorithm 4 pp.20--22](https://arxiv.org/pdf/2603.04742#page=20)

解密后的 `mid_res[idx]` 仍是排序后的物理行顺序。Algorithm 1 lines 14--19 用：

```text
for rm_idx in row_map:
    Res[rm_idx] = mid_res[idx]
```

将其恢复为原矩阵的逻辑输出 `M v`。因此 `RowMap` 不参与 Cloud 端乘法，但最终接收者若要得到原逻辑行序就必须拥有它或等价的 reconstruction map。

原文只形式化了一个静态 CSSC 实例的一次聚合输出。§4.7 对超过 slot 高度的矩阵只说明按行分区，没有形式化多 ciphertext 输出的拼接接口；它也没有 base/delta 多 component、不同 component 各自 `RowMap`、Output Share、OutputPlan 或零和盲化。因此这些语义不能标成“原 CSSC 已提供”。

## 7. 原文内部不一致：必须显式冻结解释

这些冲突不能用作者代码消歧，因为没有定位到公开实现。

1. **sparsity 是否向 Cloud 公开。** §3.1 p.9 说 zero/non-zero positions “publicly known and shared among all parties”；§3.3 pp.9--10 随后又说 Cloud 不知道 non-zero locations、row/column indices 或 row-reordering map，并说重组元数据只在 A/B 之间交换。[p.9](https://arxiv.org/pdf/2603.04742#page=9)，[p.10](https://arxiv.org/pdf/2603.04742#page=10) 不能据此声称原论文给出了完全一致的 support-hiding 泄露定义。

2. **`ColumnIndex` 的接收者。** Algorithm 1 line 4、Figure 3 和 §3.3 都是 A -> B，Cloud 只收 ciphertext；但 Algorithm 2 前的 p.18 正文写了 “pass the column index to cloud for multiplication”。[p.18](https://arxiv.org/pdf/2603.04742#page=18) 这与主算法直接冲突。若采用 Hidden-RowMap/Hidden-ColumnIndex 模式，必须注明这是选择与 Algorithm 1、Figure 3、§3.3 一致的解释，而不是声称全文无歧义。

3. **Algorithm 1 / 2 接口不闭合。** Algorithm 1 把 `generateChunk(M)` 写成返回 `value, column_index, row_map, param`；Algorithm 2 的 header 说 chunk 含 `(Value, ColumnIndex)`，正文却只 append `chunk`，最后仅 return `chunks, row_counts, col_counts`，也不输入或返回 `RM`。[pp.16, 18](https://arxiv.org/pdf/2603.04742#page=16) 因此可继承其结构语义，不能把伪代码签名当成已通过实现验证的 API 合同。

4. **secret-key holder / result recipient 未冻结。** Algorithm 1 line 13 写 Cloud 把 `ct_res` 发给 Client A，紧接着又允许 “Client A or Client B (Secret-Key Holder)” 解密；系统模型没有指定唯一密钥持有者。[p.16](https://arxiv.org/pdf/2603.04742#page=16) 若本项目指定 Client B 为 secret-key holder 和 result recipient，这是本项目协议决策；同时必须让 B 得到版本匹配的 `RowMap` / OutputPlan。

5. **A -> B 通信表不能证明完整 `ColumnIndex` 已被计费。** Table 7 报告 `stat96v5` 的 A -> B 通信仅 920 Bytes，但同文 Table A.9 给出 233,921 个非零和 75,779 列；直接 bit-pack 一个带 padding sentinel 的全长全局 CI 就约需 `233921 * 17 / 8 > 497 KB`。原文没有说明能把任意 CI 压到 920 Bytes 的编码、缓存前提或 B 预先持有 support 的机制。[Table 7 pp.32--33](https://arxiv.org/pdf/2603.04742#page=32)，[Table A.9 p.39](https://arxiv.org/pdf/2603.04742#page=39) 因而不能把 Table 7 的 A -> B 数字当成 Algorithm 1 完整 `ColumnIndex` 传输的已验证成本；Day 1 必须按本项目实际序列化表示独立计数。

## 8. 对 manifest 的最小含义

当前 v2.1b manifest 应至少冻结以下事实；前三项来自原 CSSC 主路径，版本与 OutputPlan 是本项目为动态场景补上的义务：

- `matrix_owner = Client A`，`query_owner = Client B`，Cloud 为 semi-honest evaluator；
- `ColumnIndex.addressing = global-original-matrix-column`，有效域是 `-1` 或 `[0,matrix.cols)`，`-1` 仅表示 padding；明确禁止 modulo `effective_slots`；
- `ColumnIndex` 由 A 明文交给 B，B 被允许获知相应 sparsity metadata；Hidden 模式禁止 Cloud 得到 `ColumnIndex` 与 `RowMap`，并说明这是对原文冲突的冻结解释；
- `matrix.cols` 与 `packing.effective_slots` 是独立字段，允许 `matrix.cols > effective_slots`；
- 每个 component / matrix version 的每个 CSSC value chunk 都有同形状 `ColumnIndex`；B 每次查询为每个 chunk 生成一个 query ciphertext；
- `ColumnIndex`、chunk layout、`RowMap` / OutputPlan 都绑定同一个 `version_id`。只有完成版本同步后才能接受查询；A -> B metadata bytes 必须计入 publication/update communication；
- 若 Client B 是 secret-key holder / result recipient，manifest 必须授权并要求 A -> B 交付版本匹配的 `RowMap` 或完整 OutputPlan；不能只写“Cloud 不知道 RowMap”而遗漏最终恢复方；
- 对多个 component，原 CSSC 的单一 `RM` 不够。必须使用 `(component_id, output_block_id, physical_lane) -> logical_coordinate` 的 OutputPlan；其 blinding 与重构属于本项目扩展，不得归因于原论文。

## 9. 对 Day 1 数据结构与计数的最小含义

仅有 `row_lengths` 足以做一个明确标注的 ciphertext-count proxy，但不足以模拟 `ColumnIndex` 更新、padding/tombstone 可用性或 query reorganization。Day 1 的语义路径至少需要：

1. 输入保存每行真实的全局列号（或完整 `(row, global_col)` support），不能只保存度数；
2. 每个 chunk 保存逐槽 `global_column_indices`、padding `-1`、槽到逻辑行的映射以及版本标识；
3. 插入复用 padding 时，把该槽从 `-1` 改为真实全局列号，并触发该版本的 A -> B `ColumnIndex` 同步；删除若保留 tombstone，则应明确 CI 是否保留，不能只减一个“padding 总数”；
4. 每个查询的 `query_ciphertexts`, encryptions 与 B -> Cloud upload bytes 按 `query_count * sum_component_chunk_count` 计；不得按窗口数、一个全局查询 ciphertext 或 `ceil(matrix.cols/effective_slots)` 计；
5. A -> B `ColumnIndex` bytes 按实际发生的 layout/version publication 计，与每查询的 encrypted upload 分栏；
6. preflight 必须放置至少一个实际非零坐标满足 `global_col >= effective_slots`，验证重组值等于 `query[global_col]`，并让任何 modulo 实现失败；只把 `matrix.cols` 设大但不触及高列号不构成该测试；
7. 多 horizontal output blocks 只能按 OutputPlan 拼接；多个重叠 components 才按逻辑坐标求和。原 Algorithm 1 的单输出 `ct_res` 不能被用来证明任意多 component 返回可直接相加。

## 10. 禁止写入论文的 claim

- 禁止称 `ColumnIndex` 为 chunk-local slot index、连续列块编号，或声称可对 `effective_slots` 取模。
- 禁止称一次查询只需一个 ciphertext；应写成每个 CSSC value chunk 一个对应 query ciphertext。
- 禁止声称原 CSSC 论文已经定义动态版本同步、增量更新、base/delta component、OutputPlan 或 F1-M 零和盲化；原文明确把 evolving sparsity 的 incremental update 留作未来工作。[PDF pp.34--35](https://arxiv.org/pdf/2603.04742#page=34)
- 禁止声称原论文无歧义地向 Cloud 隐藏 sparsity pattern；必须披露 §3.1 与 §3.3 / Algorithm 1 的矛盾，并说明本项目采用哪一条。
- 禁止声称原论文固定 Client B 为唯一 secret-key holder / result recipient；这是本项目的角色冻结。
- 禁止声称多结果 ciphertext 可以全部相加；不同 horizontal output blocks 是拼接，不同 component 只有在 OutputPlan 指向同一逻辑坐标时才求和。
- 禁止直接引用 Table 7 的 A -> B Bytes 作为完整全局 `ColumnIndex` 同步成本；其口径与 Algorithm 1 / 3 所需的逐槽 CI 没有闭合。
- 禁止声称已复现或核对作者实现。当前证据只支持“按作者 PDF/TeX 伪代码重建并独立实现”。

## 11. 可安全用于论文的方法描述

> CSSC keeps each nonzero's original matrix-column address in a per-slot `ColumnIndex`. Client A transmits the chunked index metadata to Client B, which gathers the dense query in plaintext and encrypts one aligned query vector per CSSC value chunk. Consequently, the global query-address domain is independent of the ciphertext-slot domain: a column identifier may exceed the number of usable slots, while each gathered chunk must still fit one ciphertext. Our dynamic protocol version-binds this metadata and the corresponding reconstruction plan; this versioning and multi-component output handling are extensions beyond the static CSSC protocol.

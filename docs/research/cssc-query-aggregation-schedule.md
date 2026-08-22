# CSSC query reorganization 与逐 chunk 归约：rotation/add schedule 一手核验

核验日期：2026-08-22（Asia/Shanghai）

核验对象：Yang Gao 等，*Efficient Privacy-Preserving Sparse Matrix-Vector Multiplication Using Homomorphic Encryption*，arXiv:2603.04742v1 / *Information Sciences* 739 (2026) 123180。本文只回答：CSSC 的 query reorganization、每个 chunk 的列归约、非 2 幂宽度、跨 chunk 聚合以及本仓库相关命名和计数应如何归属。

## 1. 来源和结论边界

只使用以下一手材料：

- [arXiv 作者记录（v1，2026-03-05）](https://arxiv.org/abs/2603.04742)；
- [arXiv 官方 PDF](https://arxiv.org/pdf/2603.04742)；
- [arXiv 官方 HTML（由作者 TeX 生成，含可定位的算法行）](https://arxiv.org/html/2603.04742v1)；
- [arXiv 官方 TeX source](https://arxiv.org/e-print/2603.04742)，主文件 `mainNoTrack.tex`；
- [ScienceDirect 正式出版页面](https://www.sciencedirect.com/science/article/pii/S0020025526001118)，DOI [10.1016/j.ins.2026.123180](https://doi.org/10.1016/j.ins.2026.123180)；
- CSSC Algorithm 4 明确声称采用的原始 `totalSum` 来源：Halevi--Shoup, *Algorithms in HElib*，[ePrint 2014/106，§4.1，PDF p.10](https://eprint.iacr.org/2014/106.pdf#page=10)。这是被 CSSC 直接引用的算法一手来源，不是二手解释。

本地复核的 CSSC arXiv v1 PDF SHA-256 为 `ee4d1b5f15be58e8c4815bc595a58b486ac56c05529da973b05b01a5c3bcd485`，TeX source tarball SHA-256 为 `125d878832522d76df6516cf749fe7c1ba94604682bc25363fa4e0dfe37e6403`。PDF、TeX、arXiv 记录和出版页面没有列出作者代码或 artifact URL；论文只说实验“uses Pyfhel”。因此无法用作者实现消解伪代码歧义，也不得写成“已与作者代码核对”。[实验设置：PDF p.26 / HTML §5](https://arxiv.org/html/2603.04742v1#S5)

## 2. 结论先行

| 问题 | 核验结论 | 证据/分类 |
|---|---|---|
| CSSC 是否只支持 `w-1` 次线性归约 | **否。** Algorithm 4 明写 bit-decomposition / doubling schedule | 论文明确，[Algorithm 4 lines 3--13](https://arxiv.org/html/2603.04742v1#alg4)，PDF pp.20--22 |
| 仓库 `f(w)=floor(log2 w)+popcount(w)-1` 是否有论文依据 | **有操作数依据。** 它正好等于 Algorithm 4 纸面循环产生的 HE-Rot 数和 chunk 内 HE-Add 数 | 由算法逐行必然推导；论文没有打印该闭式 |
| Algorithm 4 对非 2 幂 `w` 是否按字面正确 | **否。** set-bit 分支把 HElib 的 `original input + Rot(acc,1)` 写成了 `acc + Rot(acc,1)`；`w=3` 即产生重复权重 | 论文原文与其直接引用的一手算法对照后可证 |
| CSSC 是否要求把宽度 pad 到 next power of two | **没有。** Algorithm 2 贪心纳入“仍能放进容量”的连续 CSSC 列，`c=i-start`，没有 2 幂约束或 next-power padding | 论文明确，[Algorithm 2 lines 4--16](https://arxiv.org/html/2603.04742v1#alg2)，PDF p.18 |
| CSSC 的一手引用链中有没有支持任意宽度的对数 schedule | **有，但需要把 Algorithm 4 line 9 改回所引用的 HElib 形式：`w <- ctV + Rot(w,r)`。** 其 rot/add 数仍为 `f(w)` | 来自被引用的 `totalSum`；不是 CSSC 伪代码按字面行为 |
| 本仓库当前分支实际执行什么 | 通用 query compiler 生成 stored-power/prefix 纠正 DAG：保存 2 幂宽度的部分和，再按 `w` 的二进制前缀合并；共 `f(w)` 个抽象 Rot/Add 节点 | 本仓库当前的 CSSC-compatible executable DAG；[compiler 实现](../../src/dynamic_cssc/query_compiler.py#L404-L451) |
| 仓库何时使用过 `w-1` direct-linear schedule | commit `81ba1f2` 的 strong CSSC base 从 original product 执行 `k*h, k=1..w-1` 的直接旋转；当前分支已不再如此 | 仓库历史实现，[固定 commit 源码](https://github.com/leemaple/dynamic-cssc-spmv/blob/81ba1f2c875717967896325c0664b9ffd782f7a5/src/dynamic_cssc/strong_execution.py#L466-L478) |
| 论文 Table 3 的 `n_ct log2 Cmax` 是精确计数吗 | **不是。** 它是渐近/简化表达，既不含非 2 幂的 popcount 项，也未闭合跨 chunk 加法 | 论文表格与 Algorithm 4 对照即可确认 |

最重要的表述边界是：`f(w)` **不是凭空发明的 heuristic**，它精确复现了 CSSC Algorithm 4 的纸面 rot/add 节点数；对当前仓库而言，它也是 stored-power/prefix DAG 的实际**抽象节点数**。但由于论文的非 2 幂分支按字面不正确、没有作者代码可核，而当前仓库 DAG 又不是论文 Algorithm 4 或 HElib `TS` 的逐行 trace，论文引用时仍应称为 **paper-intended corrected-totalSum abstract count**；不能称为“已验证的 CSSC 作者实现成本”或已闭合的 primitive-key 成本。

## 3. CSSC chunk 与 query reorganization 的论文语义

CSSC 定义为

```text
CSSC(M) = (VA, CI, RM, CP)
```

其中 `CI` 是每个非零元素在原矩阵中的 original column index，`RM` 是排序后物理行到原矩阵行的映射；`VA` 和 `CI` 以左对齐矩阵的 column-major 顺序保存。[§4.3 / PDF p.14](https://arxiv.org/html/2603.04742v1#S4.SS3)，[Appendix B, Algorithm 5](https://arxiv.org/html/2603.04742v1#alg5)

Algorithm 2 把连续的 CSSC rank-columns 贪心装入一个 ciphertext chunk，令 chunk 高为首列高度 `h=NNZ[start]`、宽为 `c=i-start`，并把每列 pad 到 `h`；value padding 是 `0`，`ColumnIndex` padding 是 `-1`。算法没有要求 `c` 为 2 幂，也没有将其扩至 `2^ceil(log2 c)`。[Algorithm 2 lines 4--16 / PDF p.18](https://arxiv.org/html/2603.04742v1#alg2)

Client B 对每个 chunk 的 `ColumnIndex` 独立执行：

```text
reorg[q][lane] = query[CI[q][lane]]   if CI[q][lane] >= 0
reorg[q][lane] = 0                    otherwise
```

然后每个 reorganized vector 分别加密；Cloud 按相同下标把一个 value ciphertext 与一个 query ciphertext 相乘。[Algorithm 3 / PDF p.19](https://arxiv.org/html/2603.04742v1#alg3)，[Algorithm 1 lines 1--12 / PDF p.16](https://arxiv.org/html/2603.04742v1#alg1)

因此“每个 CSSC value chunk 对应一个 query ciphertext”是 Algorithms 1 与 3 的直接组合；“query reorganization”是本仓库对作者 `Reorganization of Dense Vector` / `reorgVector` 的系统化简称，不是论文中的固定术语。论文没有 query ID、version binding、metadata cache、component 或 query compiler。

## 4. Algorithm 4 的纸面逐 chunk schedule

设一个乘积 ciphertext `ctV` 保存 column-major 的 `h x w` chunk；论文变量为 `r=h, c=w`。Algorithm 4 lines 3--13 原样等价于：[PDF pp.20--22](https://arxiv.org/pdf/2603.04742#page=20)，[HTML Algorithm 4](https://arxiv.org/html/2603.04742v1#alg4)

```text
acc = ctV
e = 1
for j = numBits(w)-2 down to 0:
    acc = acc + Rot(acc, e*h)
    e = 2*e
    if bit_j(w) == 1:
        acc = acc + Rot(acc, h)      # paper-literal line 9
        e = e + 1
```

这里每个 column block 占连续 `h` slots，所以一次 block displacement `d` 对应 slot rotation `d*h`。论文明确给 `numBits(5)=3`、`numBits(21)=5`，并声称该循环是 HElib `totalSum`。[Algorithm 4 后解释段](https://arxiv.org/html/2603.04742v1#S4.SS5.SSS0.Px1)

### 4.1 纸面 rot/add 闭式

令 `k=floor(log2 w)`。外层循环固定执行 `k` 次，每次恰有一 Rot 和一 Add；被检查的是除最高位外的 `k` 个 bits，其中 1 的数量是 `popcount(w)-1`，每个 set bit 再触发一 Rot 和一 Add。因此，对 `w>=1`：

```text
R_paper(w) = A_intra,paper(w)
           = floor(log2 w) + popcount(w) - 1.
```

这是从 [Algorithm 4 lines 5--11](https://arxiv.org/html/2603.04742v1#alg4) 的精确推导。例如 `w=7 (111b)` 给 `2+3-1=4` 次；`w=8` 给 `3+1-1=3` 次。当前仓库 [`aggregation_rotations_proxy`](../../src/dynamic_cssc/cssc.py#L41-L45) 正是这个闭式；该本地链接描述当前未提交工作树，不伪装成远程 commit 永久链接。

### 4.2 非 2 幂的字面正确性失败

CSSC Algorithm 4 声称来自 Halevi--Shoup `totalSum`，但关键 set-bit 行抄写不同：

```text
Halevi--Shoup TS line 5: acc <- original + Rot(acc, 1)
CSSC Algorithm 4 line 9: acc <- acc      + Rot(acc, 1)
```

见 [Halevi--Shoup §4.1, TS(v), PDF p.10](https://eprint.iacr.org/2014/106.pdf#page=10) 与 [CSSC Algorithm 4 line 9](https://arxiv.org/html/2603.04742v1#alg4)。把 HElib 的一个 slot 换成 CSSC 的一个 `h`-slot column block，只需把 rotation `1` 缩放为 `h`；是否使用 original input 不会因此改变。

`w=3` 已构成最小反例。令三个 column blocks 为 `a,b,c`，记 `R` 为向目标行块方向旋转一个 column block：

```text
first step:     acc1 = v + R(v)             -> coefficients [1,1]
CSSC line 9:    acc2 = acc1 + R(acc1)       -> [1,2,1]
correct TS:     acc2 = v    + R(acc1)       -> [1,1,1]
```

所以 CSSC 字面版本在被最终 mask 保留的目标 `h` lanes 中得到 `a+2b+c`，而不是 `a+b+c`。该失败只在 lower bit 为 1 时出现；2 幂宽度没有 set-bit 分支，普通 doubling schedule 是正确的。论文 Figure 7 caption 把 `1,2,4` 标成三个 chunk 的 column counts，因此示例不会暴露非 2 幂 set-bit 分支。[Figure 7 caption / PDF p.20](https://arxiv.org/html/2603.04742v1#S4.F7)

同一 caption 又说三个 chunks 分别 rotate `1,2,4` 次；这也不能作为精确计数，因为 Algorithm 4 对宽度 `1,2,4` 的循环次数分别是 `0,1,2`。因此一手论文内部同时存在“Algorithm 4 逐行 schedule”“Figure 7 叙述计数”“Table 3 简化计数”三个不一致口径；只有算法行本身足以导出 `f(w)`，但其非 2 幂数值正确性仍受上述 line-9 错误影响。

论文正文仍声称循环结束后每行包含全部 `c` 列的和；这是一项与伪代码不相容的声明，而不是额外的修正规则。[Algorithm 4 解释段末句](https://arxiv.org/html/2603.04742v1#S4.SS5.SSS0.Px1)

## 5. 五种 schedule 口径必须分开

### 5.1 Corrected `totalSum`：任意宽度，`f(w)` 次

若按论文明确引用的 HElib 算法恢复 set-bit 行，得到：

```text
original = ctV
acc = original
e = 1
for j = numBits(w)-2 down to 0:
    acc = acc + Rot(acc, e*h)
    e = 2*e
    if bit_j(w) == 1:
        acc = original + Rot(acc, h)
        e = e + 1
```

Halevi--Shoup 给出的 invariant 是：`acc` 已聚合原向量中连续 `e` 个项，且循环后 `e` 的二进制前缀等于目标宽度；该算法明确适用于一般 `n`，不是只适用于 2 幂。[§4.1, PDF p.10](https://eprint.iacr.org/2014/106.pdf#page=10) 将 slot 单元扩为 `h`-slot block 后，第一组 `h` lanes 可得到该 chunk 的逐行和。其 Rot/Add 节点数仍是 `f(w)`。

这项结论是“CSSC 引用算法的最小纠错解释”，不是已经由 CSSC 作者代码证实的实现细节。若声称执行的是 HElib `TS` 的这条 trace，必须显式保留 `original=ctV`，且 set-bit 分支的 Add 左操作数是 `original`；其他等价纠正 DAG 必须用自己的依赖和 shifts 表述，不能写成这条 HElib trace。

### 5.2 当前 stored-power/prefix DAG：任意宽度，`f(w)` 次

当前通用 query compiler 使用另一条精确的 CSSC-compatible schedule：

```text
P[1] = ctV
for s = 1, 2, 4, ... while 2*s <= w:
    P[2*s] = P[s] + Rot(P[s], s*h)

prefix = largestPowerOfTwoAtMost(w)
acc = P[prefix]
for bit = prefix/2, prefix/4, ... , 1:
    if bit is set in w:
        acc = acc + Rot(P[bit], prefix*h)
        prefix = prefix + bit
```

第一段以 `floor(log2 w)` 个 Rot/Add 保存 `P[1],P[2],P[4],...`；第二段对除最高位外每个 set bit 各用一个 Rot/Add，因而合计仍为 `f(w)`。例如 `w=7` 产生 shifts `h,2h,4h,6h`，其旋转源依次是 `P[1],P[2],P[2],P[1]`。这一依赖图在最终保留的前 `h` lanes 中给出正确逐行和，且无需 next-power 宽度 padding。[当前本地 `query_compiler.py` lines 404--451](../../src/dynamic_cssc/query_compiler.py#L404-L451)

这是本项目的纠正 executable DAG：它与论文 Algorithm 4 的字面 self-add 不同，也不是 HElib `TS` 的逐行 trace。“CSSC-compatible”在此只表示它在 CSSC column-major chunk 上实现所需的归约语义，且与 paper-intended count 相同；不表示 CSSC 作者发表过这条 DAG。

### 5.3 Direct linear：任意宽度，`w-1` 次

另一条无 bit-branch 歧义的 schedule 是：

```text
acc = ctV
for k = 1 .. w-1:
    acc = acc + Rot(ctV, k*h)
```

它每次都旋转 original product ciphertext，恰有 `w-1` Rot 和 `w-1` Add。这是一条有效的通用备选 schedule，也是本仓库在历史 commit `81ba1f2` 的 strong CSSC base 采用的 schedule：[固定 commit 源码 lines 466--478](https://github.com/leemaple/dynamic-cssc-spmv/blob/81ba1f2c875717967896325c0664b9ffd782f7a5/src/dynamic_cssc/strong_execution.py#L466-L478)。它是仓库自定义的保守 executable schedule，不是 CSSC Algorithm 4 的逐行复现，也不再是当前分支的 strong schedule。

### 5.4 Next-power doubling：论文未给，且有容量前提

若先把 chunk 从 `w` 列显式补零到 `p=2^ceil(log2 w)` 列，再用 shifts `h,2h,...,(p/2)h`，可在 `ceil(log2 w)` 次 Rot/Add 后得到精确和。但它要求 `h*p <= N_slots`；当原 `h*w` 已贴近容量时，额外 dummy columns 未必装得下。

CSSC Algorithm 2 只把**各已选列**补到高度 `h`，没有把列数补到 next power；Algorithm 4 也直接读原始 `cList`。因此 next-power schedule 是可选的仓库/实现设计，不得归因于 CSSC。[Algorithm 2 lines 10--16](https://arxiv.org/html/2603.04742v1#alg2)，[Algorithm 4 inputs](https://arxiv.org/html/2603.04742v1#alg4)

### 5.5 对比表

| schedule | 任意 `w` 正确 | chunk 内 Rot/Add | 额外容量 | 归属 |
|---|---:|---:|---:|---|
| CSSC Algorithm 4 按字面 | 否；非 2 幂 set-bit 分支重复计权 | `f(w)` | 无 | 论文明确，但存在错误 |
| corrected HElib `totalSum` | 是 | `f(w)` | 无；需保留 original ciphertext | 被论文引用的一手算法 + 可推导 block scaling |
| stored-power/prefix corrected DAG | 是 | `f(w)` | 无布局扩容；direct-key 前提见 §7 | 当前仓库通用 compiler；不是论文/HElib 的逐行 trace |
| direct linear from original | 是 | `w-1` | 无 | 通用备选；仓库 commit `81ba1f2` 的历史 strong base |
| pad-to-next-power doubling | 是 | `ceil(log2 w)` | 需 `h*nextPow2(w)` slots | 通用可选实现；CSSC 未规定 |

## 6. 跨 chunk aggregation 与总操作数

Algorithm 4 对每个已做完 intra-chunk aggregation 的 ciphertext 构造 plaintext mask：前 `h_i` slots 为 1，其余为 0；然后执行 `res <- res + intraRes[i]*mask_i`。[Equations (1)--(2) 与 Algorithm 4 lines 15--20 / PDF pp.20--22](https://arxiv.org/html/2603.04742v1#S4.SS5.p4)

设一个输出 row partition 有 `m` 个 chunks，宽度为 `w_i`：

- corrected-totalSum / 论文纸面**节点数**：intra rotations `sum_i f(w_i)`，intra additions同数；
- mask multiplications：论文逐 chunk 明写一次，因此是 `m` 次 HE-CMult；
- cross-chunk additions：按字面从 encrypted zero accumulator 加 `m` 次；若把第一个 masked ciphertext 直接赋给 accumulator，则实际只需 `m-1` 次 ciphertext additions。

论文 Table 3 报 `n_ct*log2(Cmax)` Rot 和同数 Add，只能看作简化的 `O(n_ct log Cmax)` 描述：它没有 `popcount(w_i)-1`，把不同 chunk widths 压成一个 `Cmax`，也没有明确加上跨 chunk merge。[Table 3 / PDF p.23](https://arxiv.org/html/2603.04742v1#S4.SS6.SSS2)

当前分支已用一个通用 compiler 闭合这一节点口径：compiler 对每个 CSSC chunk 调用 stored-power/prefix 归约，再显式生成 `m-1` 个 cross-chunk Add；[compiler 组装处](../../src/dynamic_cssc/query_compiler.py#L634-L674)。simulator 调用 `compile_query` 并直接读取编译结果的 `cloud_counts`；[simulator 当前本地源码](../../src/dynamic_cssc/simulator.py#L94-L123)。strong adapter 同样调用 `compile_query`，并把该 `cloud_plan` 和 `cloud_counts` 放入 strong bundle；[strong adapter 当前本地源码](../../src/dynamic_cssc/strong_execution.py#L195-L259)。因此两者当前共享同一条 executable DAG，在**抽象 DAG 节点**边界不再存在 `f(w_i)` predictor 对 `w_i-1` executor 的差异。

该差异只是历史状态：在 commit `81ba1f2`，simulator 使用 `sum_i f(w_i)` 口径（[历史源码](https://github.com/leemaple/dynamic-cssc-spmv/blob/81ba1f2c875717967896325c0664b9ffd782f7a5/src/dynamic_cssc/simulator.py#L98-L113)），而 strong base 执行 `w_i-1` direct-linear 归约（[历史源码](https://github.com/leemaple/dynamic-cssc-spmv/blob/81ba1f2c875717967896325c0664b9ffd782f7a5/src/dynamic_cssc/strong_execution.py#L466-L478)）。这个历史 mismatch 不得再写成当前分支状态。

## 7. Rotation key / primitive cost 尚未闭合

Algorithm 4 把 `HE.Rot(acc,k)` 当作一个抽象操作；其中 `k=e*h`，对非 2 幂宽度以及任意 chunk height，`k` 通常不是 2 的幂。[Algorithm 4 lines 5--10](https://arxiv.org/html/2603.04742v1#alg4)

但实验设置只说生成“powers-of-two rotation keys”，没有给出：

- 每个 `e*h` 是否存在 direct key；
- 若只用 power-of-two keys，Pyfhel/底层库如何组合目标 rotation；
- 一个纸面 `HE.Rot` 会触发多少 primitive rotations / key-switches；
- 组合 rotation 的 noise、latency 和 key catalog 计费。

见 [PDF p.26 / HTML §5 首段](https://arxiv.org/html/2603.04742v1#S5.p2)。因此 `f(w)` 是 Algorithm 4 的**抽象 Rot 节点数**，不是由一手 artifact 闭合的 key-switch 数或 wall-clock 次数。任何 executable implementation 都必须另行冻结：direct-key catalog，或 composite rotation 的具体分解和实际 primitive 计数。

当前 stored-power/prefix compiler 对每个 rotation node 记录精确的 `logical_shift` 并把同一整数写入 `openfhe_index`；[归约节点生成](../../src/dynamic_cssc/query_compiler.py#L419-L449)、[rotation catalog 生成](../../src/dynamic_cssc/query_compiler.py#L789-L798)。这是 plan 层的 **direct exact-shift 要求**，不是 key 已生成或成本已测量的证明。非 2 幂宽度会要求非 2 幂的精确 shifts；例如 `w=7` 的 `6h` 不能被“只有 powers-of-two keys”自动视为一次 primitive rotation。最终 executable witness 必须显式证明这些 direct keys 已配置，或冻结 composite 分解并计入所有 primitive rotations/key-switches。本次未运行 [whole-query witness workflow](../../.github/workflows/strong-whole-query-witness.yml)，当前实现的最终成功 witness 仍待闭合。

## 8. 术语和归属审计

| 术语/语义 | 归属 | 可安全表述与证据 |
|---|---|---|
| `Compressed Sparse Sorted Column (CSSC)` | CSSC 论文 | 作者提出的格式，[§4.3](https://arxiv.org/html/2603.04742v1#S4.SS3) |
| `Column Index Array CI` / `ColumnIndex` | CSSC 论文 | 保存对应非零元素的 original matrix column index；Algorithm 2 padding 为 `-1`，[§4.3](https://arxiv.org/html/2603.04742v1#S4.SS3)、[Algorithm 2](https://arxiv.org/html/2603.04742v1#alg2) |
| `Row Map Array RM` / `row_map` | CSSC 论文 | 排序后物理行对应的 original row index；Algorithm 1 解密后恢复原行序，[§4.3](https://arxiv.org/html/2603.04742v1#S4.SS3)、[Algorithm 1 lines 14--20](https://arxiv.org/html/2603.04742v1#alg1) |
| `Reorganization of Dense Vector`, `reorgVector` | CSSC 论文 | Client B 依据 CI gather dense vector，[§4.4.2 / Algorithm 3](https://arxiv.org/html/2603.04742v1#S4.SS4.SSS2) |
| “query reorganization” | 本仓库命名 | 对上述作者操作的简称；该短语未出现在作者 TeX 中，不应加引号伪装成论文术语 |
| 每 value chunk 一个 aligned query ciphertext | Algorithms 1+3 的直接推论 | 可以写“CSSC protocol implies...”，不宜写成作者定义的命名对象 |
| `Aggregation`, `rList`, `cList`、逐 chunk mask、跨 chunk sum | CSSC 论文 | [§4.5 / Algorithm 4](https://arxiv.org/html/2603.04742v1#S4.SS5) |
| `aggregation_rotations_proxy` 及闭式 `f(w)` | 本仓库名字；闭式可由论文算法推导 | [当前本地定义](../../src/dynamic_cssc/cssc.py#L41-L45)；不得声称论文打印了该公式，也不得称作者实现已验证 |
| query/version binding、per-component CI、OutputPlan、base/delta、F1-M | 本仓库扩展 | CSSC 是单一静态矩阵调用；论文把 evolving sparsity / incremental updates 列为未来工作，[§6 / PDF pp.34--35](https://arxiv.org/html/2603.04742v1#S6) |
| stored-power/prefix corrected DAG | 本仓库当前实现 | [common compiler](../../src/dynamic_cssc/query_compiler.py#L404-L451)；是 CSSC-compatible 项目 DAG，不可冒充 Algorithm 4 或 HElib 逐行 trace |
| strong base 的 `w-1` direct-linear schedule | 本仓库历史实现 / 通用备选 | [commit `81ba1f2` lines 466--478](https://github.com/leemaple/dynamic-cssc-spmv/blob/81ba1f2c875717967896325c0664b9ffd782f7a5/src/dynamic_cssc/strong_execution.py#L466-L478)；不可冒充 Algorithm 4，也不是当前 strong schedule |
| packed-COO power-of-two segment doubling | 本仓库另一 primitive | 与 CSSC chunk width 无关；不可用它证明 CSSC 要求 power-of-two width |

尤其要避免把 `ColumnIndex`、`Row Map`、dense-vector reorganization 和 Algorithm 4 aggregation 全部列为“本项目算法”；这些核心静态语义属于 CSSC。反过来，版本同步、query compiler、OutputPlan、多 component 合并与强执行计划也不能归给 CSSC。

## 9. 对后续实现和论文 claim 的最低约束

1. 引用 `f(w)` 时必须区分两层：它是“paper-intended corrected-totalSum abstract count”，同时是当前 stored-power/prefix 项目 DAG 的实际抽象节点数。后者不是 CSSC Algorithm 4 的字面 trace，也不必然是 HElib `TS` 的精确 trace。
2. 若实现精确的 HElib `TS` trace，set-bit 分支必须使用 original product ciphertext；若使用当前 stored-power/prefix DAG，则必须冻结其 `P[bit]` 旋转源和 `prefix*h` shifts。两者都不能执行 CSSC line 9 的 literal self-add。
3. simulator 与 strong adapter 当前共用 compiler；`f(w)` predictor 对 `w-1` executor 的差异只属于 commit `81ba1f2` 的历史状态。direct-linear 仍可作替代方案，但不得写成当前实现。
4. 若改用 next-power schedule，必须检查 `h*nextPow2(w) <= effective_slots` 并把 dummy-column padding 进入布局/manifest；不能说 CSSC Algorithm 2 已经做了该 padding。
5. 计数至少分开 `abstract Rot nodes`、`primitive rotation/key-switch count`、intra adds、cross-chunk adds、mask CMult；Table 3 不能充当精确执行清单。每个非 2 幂 exact shift 必须有显式 direct key 及成本，或有可审计的 composite 分解及 primitive 成本。
6. 非 2 幂 gate 至少包含 `w=3`（能抓 literal self-add）和 `w=7`（区分 `f(w)=4`、linear `w-1=6`、next-power `ceil(log2 w)=3`），并绑定实际 rotation sources、exact shifts、key catalog 与 primitive 计数。最终 cryptographic witness 仍待闭合；本次未运行 workflow、benchmark 或修改代码。

可安全写入论文的方法说明：

> CSSC packs each chunk in column-major order and reorganizes one dense-query vector per value chunk using the chunk's original-column indices. Its published Aggregation pseudocode uses a bit-decomposed total-sum schedule whose abstract rotation/add count is `floor(log2 w)+popcount(w)-1`. For non-power-of-two widths, however, the pseudocode's set-bit branch differs from the cited HElib total-sum algorithm: the HElib trace uses the original chunk product as the unrotated addend. Our current common query compiler instead realizes the required reduction with a distinct stored-power/prefix CSSC-compatible executable DAG having the same abstract count; the simulator and strong adapter both consume that DAG. It is neither the paper-literal Algorithm 4 nor necessarily the exact HElib trace. Direct `w-1` reduction remains a valid alternative and was the repository's historical strong implementation at commit `81ba1f2`. Exact non-power-of-two shifts still require explicit keys or an accounted decomposition, and a successful final witness for the current implementation is pending.

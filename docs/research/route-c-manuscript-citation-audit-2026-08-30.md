# Route C manuscript citation audit — 2026-08-30

> **Post-audit remediation.** The manuscript worktree subsequently corrected
> all three P1 findings and all four grouped P2 findings recorded below:
> Dynamic-CSR and ShieldDB now use their verified final publication metadata;
> Cash/ShieldDB/Obladi support the dynamic-system paragraph while Bonawitz alone
> supports canceling masks; CSSC is cited at the pseudocode audit; inferred
> absence cells say “Not described”; the SparseE availability statement is
> dated; and the listed page, issue, DOI, URL, publisher, and acceptance fields
> are complete. This report intentionally preserves the original findings and
> exact audited hashes as the provenance record. The remediated manuscript must
> receive a new commit-bound external review before circulation.

## Audit target and method

This report audits every citation key actually used by
`docs/paper/manuscript-draft.md` against primary or first-party records only:
publisher/DOI landing pages, official proceedings pages, author-posted arXiv or
IACR ePrint records, official project/data pages, and the OpenFHE source
repository. It does not treat search-result snippets, secondary bibliographies,
or citation aggregators as evidence. An absence claim (for example, that no
SparseE full text was publicly available) is treated as a dated search result,
not as a fact proved by the cited abstract.

The audited working-tree snapshot was:

- repository HEAD: `b5d3acfcd706f1708ba6d592a52c5e963130c5ee`;
- `docs/paper/manuscript-draft.md` SHA-256:
  `dbb79e96a6e658425761354a47de98aa10d3218f4aac3334e094d36a4845bc93`;
- `docs/paper/references.bib` SHA-256:
  `b802875d149d299edd88b13d850d3b99eef8c5b26a3924f1ab9b988bde0d0164`.

Line numbers below refer to those exact file bytes. The manuscript uses 26
distinct citation keys, and all 26 resolve to an entry in `references.bib`.

Severity means:

- **P0** — central claim is unsupported or materially false in a way that can
  invalidate the paper's contribution boundary.
- **P1** — a real claim-attribution or bibliographic error that should be fixed
  before circulation or submission, but does not presently invalidate the core
  Route C contribution.
- **P2** — precision, citation placement, dated-availability, or bibliographic
  completeness issue.

## Executive verdict

| Severity | Count | Freeze consequence | Exact fixes |
|---|---:|---|---|
| **P0** | **0** | No primary-source contradiction of the narrow contribution boundary. | None. |
| **P1** | **3** | Fix before manuscript freeze. | `references.bib:206-218` / `king2016dynamiccsr`; `references.bib:126-133` / `vo2021shielddb`; `manuscript-draft.md:175-178` / `cash2014dynamic`, `vo2021shielddb`, `crooks2018obladi`, `bonawitz2017secureagg`. |
| **P2** | **4 grouped** | May follow the P1 freeze fixes, but complete before submission. | Local CSSC citation at `manuscript-draft.md:123-130`; absence-of-feature wording at `:136-143`; dated SparseE boundary at `:139`; final-publication fields listed in P2-4. |

The P0 result means the audit found no primary-source contradiction of the
manuscript's narrow novelty boundary: version-bound publication and
reconstruction for mutable CSSC state, rather than a new HE primitive, first
encrypted index, first sparsity-aware encrypted multiplication, or first random
sharing.

The 2025–2026 comparison boundary is otherwise well grounded. CSSC, Lodia,
CipherSkip, diagonal packing, the CPU/GPU unstructured-sparsity papers, SparseE's
public abstract, and Damie et al. all exist with the authors and technical scope
reported in the manuscript. The OpenFHE `v1.5.1` release is also exactly the
recorded source commit.

## P1 findings

### P1-1 — `king2016dynamiccsr` points to an unrelated publication

- **Manuscript:** `docs/paper/manuscript-draft.md:153`, key
  `@king2016dynamiccsr`.
- **Bibliography:** `docs/paper/references.bib:206-218`.
- **Problem:** DOI
  [`10.1007/978-3-319-43659-3_25`](https://doi.org/10.1007/978-3-319-43659-3_25)
  resolves to Long Cheng and Spyros Kotoulas, “Efficient Large Outer Joins over
  MapReduce,” pages 334–346. It is not a King/Gilray/Kirby/Might sparse-matrix
  paper. The current entry combines the title of an author-posted extended
  Dynamic-CSR paper with unrelated Euro-Par volume, page, and DOI fields.
- **Claim verdict:** the manuscript's substantive precedent claim is supported,
  but not by the current formal citation. The primary published work is James
  King, Thomas Gilray, Robert M. Kirby, and Matthew Might, “Dynamic Sparse-Matrix
  Allocation on GPUs,” in *High Performance Computing: ISC High Performance
  2016*, LNCS 9697, pages 61–80, DOI
  [`10.1007/978-3-319-41321-1_4`](https://doi.org/10.1007/978-3-319-41321-1_4).
  The [official Springer proceedings
  record](https://link.springer.com/book/10.1007/978-3-319-41321-1) lists the
  chapter and pages; the authors' [extended Dynamic-CSR
  manuscript](https://thomas.gilray.org/pdf/dynamic-csr-extended.pdf) directly
  supports dynamic inserts, segmented row capacity, and efficient SpMV.
- **Required correction:** replace the entry's title, venue, volume, pages, DOI,
  URL, and editors with the ISC High Performance record. The stable cite key may
  remain `king2016dynamiccsr`.

### P1-2 — `vo2021shielddb` is a hybrid rather than a valid publication record

- **Manuscript:** `docs/paper/manuscript-draft.md:177`, key
  `@vo2021shielddb`.
- **Bibliography:** `docs/paper/references.bib:126-133`.
- **Problem:** the entry is typed as an arXiv `@misc`, carries arXiv identifier
  `2003.06103`, but assigns year 2021. The [author-posted arXiv
  record](https://arxiv.org/abs/2003.06103) is from 2020. The final journal
  article appeared in *IEEE Transactions on Knowledge and Data Engineering*
  35(4), pages 4236–4252, in 2023, DOI
  [`10.1109/TKDE.2021.3126607`](https://doi.org/10.1109/TKDE.2021.3126607).
  The publisher DOI contains 2021 because that is the online-publication/DOI
  assignment year; it is not the issue year. The [authors' institutional
  record](https://research.monash.edu/en/publications/shielddb-an-encrypted-document-database-with-padding-countermeasu/)
  gives the final volume, issue, pages, DOI, and 2023 publication date.
- **Claim verdict:** ShieldDB does support continuously updated encrypted
  document storage, leakage through observable access patterns, and padding
  countermeasures. It does **not** establish the canceling-mask claim made in the
  immediately preceding sentence; that attribution problem is P1-3 below.
- **Required correction:** convert this to the 2023 `@article` record (the cite
  key may remain stable), adding journal, volume `35`, issue `4`, pages
  `4236--4252`, year `2023`, DOI, and URL.

### P1-3 — the canceling-mask sentence has an over-broad citation bundle

- **Manuscript:** `docs/paper/manuscript-draft.md:175-178`.
- **Keys:** `@cash2014dynamic`, `@vo2021shielddb`, `@crooks2018obladi`, and
  `@bonawitz2017secureagg`.
- **Problem:** grammatically, all four citations attach to “Canceling one-time
  masks also predate this work.” Only Bonawitz et al. directly supports that
  proposition: its secure-aggregation protocol uses pairwise random masks with
  opposite signs so that they cancel in the aggregate. See the [ACM DOI
  record](https://doi.org/10.1145/3133956.3133982), [Google Research publication
  page](https://research.google/pubs/practical-secure-aggregation-for-privacy-preserving-machine-learning/),
  and [author-posted IACR ePrint](https://eprint.iacr.org/2017/281.pdf).
- Cash et al. supports dynamic searchable encryption and explicit update/search
  leakage ([official NDSS page](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/dynamic-searchable-encryption-very-large-databases-data-structures-and-implementation/));
  ShieldDB supports continuously updated encrypted storage and padding
  countermeasures ([arXiv](https://arxiv.org/abs/2003.06103)); and Obladi supports
  oblivious serializable transactions, epochs, and delayed commit ([official
  USENIX page](https://www.usenix.org/conference/osdi18/presentation/crooks)).
  None is the right direct source for the pairwise canceling-mask statement.
- **Required correction:** place Cash, ShieldDB, and Obladi after the dynamic
  encrypted-system sentence at `:161-164`; cite Bonawitz alone after the
  canceling-mask sentence at `:175-178`. This preserves all four relevant
  precedents without implying that each contains the same mask construction.

## P2 findings

### P2-1 — cite CSSC locally for the pseudocode audit

- **Manuscript:** `docs/paper/manuscript-draft.md:123-130`.
- **Current key:** only `@halevi2014algorithms` appears at `:130`.
- **Assessment:** the HElib paper supports the SIMD `totalSum` family
  ([Springer DOI](https://doi.org/10.1007/978-3-662-44371-2_31), [IACR
  ePrint](https://eprint.iacr.org/2014/106)). It does not support a statement
  about ambiguity in CSSC's printed pseudocode or the manuscript's exact
  non-power-of-two count. Those are clearly labelled as this project's source
  audit and compatibility correction, which avoids substantive overclaim, but
  the audited object should still be cited locally.
- **Recommended correction:** add `@gao2026cssc` after “printed CSSC aggregation
  pseudocode” or after “paper-derived abstract count,” while retaining Halevi
  for the `totalSum` connection. Do not rewrite the audit conclusion as a claim
  attributed to Gao et al.

### P2-2 — use “not described” for absence-of-feature inferences

- **Manuscript:** comparison table at
  `docs/paper/manuscript-draft.md:136-143`.
- **Keys:** `@yu2025lodia`, `@mutluergil2026diagonal`,
  `@ferguson2025unstructured`, `@dagata2026gpu`, and `@he2024rhombus`.
- **Assessment:** the primary papers directly support their reported static
  representations and protocol settings. Their lack of a mutable CSSC
  publication protocol is a sound scope comparison, but the papers generally
  do not prove a theorem that mutable support is impossible. The categorical
  table value “No” is therefore slightly stronger than the source record.
- **Recommended correction:** use “Not described,” “No matrix-state publication
  protocol,” or “Outside evaluated scope.” CSSC's own static-pattern limitation
  can remain categorical because the paper states it explicitly.

### P2-3 — SparseE availability is a dated audit observation, not abstract content

- **Manuscript:** `docs/paper/manuscript-draft.md:114-115` and `:139`, key
  `@wei2026sparsee`.
- **Bibliography:** `docs/paper/references.bib:58-65`.
- **Verified boundary:** the [official DAC program
  abstract](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108)
  verifies the exact title and five authors and supports secure
  Scatter–Gather–Apply, encrypted indices, a Homomorphic Permutation Engine, and
  a Homomorphic Expansion Engine. It does not expose a full paper, DOI, pages,
  artifact link, or mutable-state protocol.
- **Assessment:** “as of 2026-08-30, no public full text, DOI, or public software
  repository was located” is appropriately dated and uses observational
  wording. It is not something the cited abstract proves and must not be
  generalized to “no implementation exists” or “no artifact exists.”
- **Recommended correction:** no immediate wording change is required. Re-run
  the official-program, DOI, arXiv/ePrint, author/institution, and repository
  checks immediately before submission, record the check date, and update both
  manuscript and BibTeX note if a public record appears.

### P2-4 — complete final-publication fields

These omissions do not presently change any claim, but completing them will
make the bibliography easier to validate and reduce copy-editing risk:

- `yu2025lodia`, `docs/paper/references.bib:11-18`: add pages `3649--3663`
  from the [ACM DOI record](https://doi.org/10.1145/3719027.3765025).
- `ferguson2025unstructured`, `:40-46`: add pages `31--38` and preferably the
  [author arXiv record](https://arxiv.org/abs/2503.09184); the DOI is
  [`10.1145/3721146.3721948`](https://doi.org/10.1145/3721146.3721948).
- `he2024rhombus`, `:67-74`: add pages `2490--2504` from the [ACM DOI
  record](https://doi.org/10.1145/3658644.3690281).
- `damie2025secure`, `:76-85`: update the note to say “Accepted in ACM CODASPY
  2026,” as the [current arXiv author record](https://arxiv.org/abs/2510.14894)
  does. Retain the preprint form until final proceedings metadata is public.
- `oneil1996lsm`, `:107-115`: add issue `4`; the final record is *Acta
  Informatica* 33(4), 351–385, DOI
  [`10.1007/s002360050048`](https://doi.org/10.1007/s002360050048).
- `stylianou2022morpheus`, `:117-124`: add
  `url = {https://arxiv.org/abs/2209.06478}` from the [author arXiv
  record](https://arxiv.org/abs/2209.06478).
- `crooks2018obladi`, `:165-171`: add pages `727--743` and publisher `USENIX
  Association` from the [official OSDI record](https://www.usenix.org/conference/osdi18/presentation/crooks).
- `bonawitz2017secureagg`, `:173-179`: add pages `1175--1191` from the [ACM DOI
  record](https://doi.org/10.1145/3133956.3133982).
- `parbat2023authorized`, `:234-243`: add pages `7796--7808`; the DOI is
  [`10.1109/TKDE.2022.3221148`](https://doi.org/10.1109/TKDE.2022.3221148).
- `snap_stackoverflow_temporal_network`, `:245-250`: add corporate author
  `{Stanford Network Analysis Project}` and an access year/date field if the
  target style requires them. The [official SNAP page](https://snap.stanford.edu/data/sx-stackoverflow.html)
  remains the authoritative object record.
- `paranjape_motifs_in_temporal_networks`, `:252-258`: add pages `601--610`, DOI
  [`10.1145/3018661.3018731`](https://doi.org/10.1145/3018661.3018731), and ACM
  publisher metadata.

## Per-key metadata and claim-support matrix

“Direct” means the cited primary record expressly supports the nearby factual
claim. “Qualified” means the representation/setting is direct but the mutable
support or public-availability conclusion is this manuscript's explicitly
limited scope inference. “Mis-scoped” means the source is relevant elsewhere but
does not directly support the sentence to which it is presently attached.

| Key | Exact manuscript location(s) | BibTeX location | Metadata verdict | Nearby-claim verdict and primary source |
|---|---|---|---|---|
| `gao2026cssc` | `docs/paper/manuscript-draft.md:58,107,136` | `docs/paper/references.bib:1-9` | **Verified.** Six authors, title, *Information Sciences* 739, article 123180, 2026, DOI all match. | **Direct.** Row sorting, left-aligned rectangles, parallel `Value`/`ColumnIndex`, `RowMap`, `ColumnPointer`, chunking, query reorganization, aggregation, and the static-pattern limitation are supported by the [publisher DOI](https://doi.org/10.1016/j.ins.2026.123180) and [author arXiv record](https://arxiv.org/abs/2603.04742). The wording at `:235-236` correctly says each value lane is *paired with* a parallel column identifier; it does not incorrectly place the identifier inside the value. |
| `yu2025lodia` | `:110,137` | `:11-18` | **Verified; pages omitted.** Add 3649–3663. | **Direct/qualified.** Batched-FHE SpMV and low-diagonal decomposition are direct; lack of a mutable publication protocol is a scope inference. [ACM DOI](https://doi.org/10.1145/3719027.3765025); [IACR ePrint](https://eprint.iacr.org/2025/1425). |
| `xiong2026cipherskip` | `:111,138` | `:20-28` | **Verified.** Authors, title, ICS 2026, pages 1220–1231, DOI match. | **Direct/qualified.** Encrypted values and structural indices, arbitrary-shaped SpGEMM, chained products, and dynamic server-side alignment are direct. “No matrix-state publication protocol” correctly states the comparison boundary. [ACM DOI](https://doi.org/10.1145/3797905.3807876); [IACR ePrint](https://eprint.iacr.org/2026/297). |
| `mutluergil2026diagonal` | `:112,140` | `:30-38` | **Verified.** | **Direct/qualified.** Row/column reordering to reduce occupied cyclic diagonals is direct; mutable CSSC support is outside the paper's described scope. [arXiv author record](https://arxiv.org/abs/2604.04683). |
| `ferguson2025unstructured` | `:113,141` | `:40-46` | **Verified; pages omitted.** Add 31–38. | **Direct/qualified.** CPU CKKS ciphertext–ciphertext unstructured sparse matrix multiplication, public sparse metadata, and the small-square-matrix setting are supported. [ACM DOI](https://doi.org/10.1145/3721146.3721948); [arXiv](https://arxiv.org/abs/2503.09184). |
| `dagata2026gpu` | `:113,142` | `:48-56` | **Verified.** | **Direct/qualified.** GPU/FIDESlib CKKS ciphertext–ciphertext sparse matrix multiplication with public structural metadata is supported; dynamic SpMV publication is outside scope. [ACM DOI](https://doi.org/10.1145/3805621.3807642); [arXiv](https://arxiv.org/abs/2604.11659). |
| `wei2026sparsee` | `:115,139` | `:58-65` | **Verified to the public-record boundary.** | **Direct within abstract/qualified for availability.** See P2-3 and the [official DAC program abstract](https://63dac.conference-program.com/presentation/?id=RESEARCH2265&sess=sess108). |
| `he2024rhombus` | `:116,143` | `:67-74` | **Verified; pages omitted.** Add 2490–2504. | **Direct/qualified.** Bob's plaintext matrix, Alice's encrypted vector, Bob's random share, and additive output shares are direct; no mutable/version-overlap protocol is described. [ACM DOI](https://doi.org/10.1145/3658644.3690281); [IACR ePrint](https://eprint.iacr.org/2024/1611). |
| `damie2025secure` | `:144` | `:76-85` | **Verified preprint; acceptance note stale.** | **Direct.** Dedicated MPC algorithms for multiplying secret-shared sparse matrices are explicit. [arXiv author record](https://arxiv.org/abs/2510.14894). |
| `kreutzer2014sellcsigma` | `:152` | `:87-96` | **Verified.** | **Direct.** Establishes SELL-C-sigma as plaintext sparse-layout precedent. [SIAM DOI](https://doi.org/10.1137/130930352). |
| `bell2008spmvcuda` | `:152` | `:98-105` | **Verified.** | **Direct.** The report defines the HYB representation as ELL plus COO and evaluates CUDA SpMV. [Author-hosted NVIDIA report](https://mgarland.org/files/papers/nvr-2008-004.pdf). |
| `oneil1996lsm` | `:153` | `:107-115` | **Verified; issue omitted.** Add issue 4. | **Direct.** Supports LSM/base-delta/periodic-merge storage precedent. [Springer DOI](https://doi.org/10.1007/s002360050048). |
| `king2016dynamiccsr` | `:153` | `:206-218` | **Incorrect; P1-1.** | **Claim supported by the correct paper, not the current DOI.** [Correct Springer proceedings](https://link.springer.com/book/10.1007/978-3-319-41321-1); [author extended paper](https://thomas.gilray.org/pdf/dynamic-csr-extended.pdf). |
| `stylianou2022morpheus` | `:154` | `:117-124` | **Verified; URL omitted.** | **Direct.** Morpheus provides dynamic sparse-matrix abstraction and runtime format selection. [arXiv author record](https://arxiv.org/abs/2209.06478). |
| `liu2024ddse` | `:166` | `:143-151` | **Verified.** | **Direct.** Volume leakage is treated separately, and padding incurs storage/communication cost. [Official USENIX paper page](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-dongli). |
| `chen2026ckksauthtree` | `:169` | `:153-163` | **Verified.** | **Direct.** Versioned root commitments and timestamps are used to reject stale/replayed verification objects after encrypted-metadata updates. [Publisher page](https://www.mdpi.com/2079-9292/15/12/2517); [DOI](https://doi.org/10.3390/electronics15122517). |
| `cash2014dynamic` | `:177` | `:135-141` | **Verified.** | **Mis-scoped at present.** Supports dynamic SSE and leakage-aware encrypted updates, not the canceling-mask sentence. [Official NDSS page](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/dynamic-searchable-encryption-very-large-databases-data-structures-and-implementation/); [IACR author manuscript](https://eprint.iacr.org/2014/853.pdf). |
| `vo2021shielddb` | `:177` | `:126-133` | **Hybrid/incorrect final metadata; P1-2.** | **Mis-scoped at present.** Supports continuous encrypted-database updates, access-pattern leakage, and padding; not canceling masks. [IEEE DOI](https://doi.org/10.1109/TKDE.2021.3126607); [arXiv](https://arxiv.org/abs/2003.06103). |
| `crooks2018obladi` | `:178` | `:165-171` | **Verified; pages/publisher omitted.** | **Mis-scoped at present.** Supports epochs, delayed commits, and oblivious serializable transactions; not the pairwise canceling-mask claim. [Official USENIX page](https://www.usenix.org/conference/osdi18/presentation/crooks). |
| `bonawitz2017secureagg` | `:178` | `:173-179` | **Verified; pages omitted.** | **Direct.** Pairwise random masks with opposite signs cancel in secure aggregation. [ACM DOI](https://doi.org/10.1145/3133956.3133982); [IACR ePrint](https://eprint.iacr.org/2017/281.pdf). |
| `parbat2023authorized` | `:180` | `:234-243` | **Verified; pages omitted.** | **Direct.** Authorized homomorphic encrypted database updates predate this work. [IEEE DOI](https://doi.org/10.1109/TKDE.2022.3221148). |
| `halevi2014algorithms` | `:130` | `:220-232` | **Verified.** | **Direct for HElib `totalSum`; qualified for the manuscript's derivation.** The exact non-power-of-two correction/count remains the present project's analysis. [Springer DOI](https://doi.org/10.1007/978-3-662-44371-2_31); [IACR ePrint](https://eprint.iacr.org/2014/106). |
| `fan2012somewhat` | `:292` | `:189-195` | **Verified.** | **Direct.** Supports Fan–Vercauteren scheme lineage. The sentence does not claim that this record is the OpenFHE implementation source. [IACR ePrint](https://eprint.iacr.org/2012/144). |
| `openfhe151` | `:293` | `:181-187` | **Verified exactly.** | **Direct.** The official `v1.5.1` release page identifies commit `1306d14`, whose full object is `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`; the bibliography links that exact source tree. [Official release](https://github.com/openfheorg/openfhe-development/releases/tag/v1.5.1); [exact source tree](https://github.com/openfheorg/openfhe-development/tree/1306d14f8c26bb6150d3e6ad54f28dfe1007689e). |
| `snap_stackoverflow_temporal_network` | `:418` | `:245-250` | **Verified object; corporate author/year can be added.** | **Direct.** The official page lists `sx-stackoverflow-a2q.txt.gz`, defines it as user-to-user answer-to-question events with UNIX timestamps, and prints the Paranjape et al. source citation. [Official SNAP dataset page](https://snap.stanford.edu/data/sx-stackoverflow.html). |
| `paranjape_motifs_in_temporal_networks` | `:418` | `:252-258` | **Verified; DOI/pages omitted.** | **Direct.** The paper and dataset attribution match the official SNAP page. The final ACM record is WSDM 2017, pages 601–610, DOI [`10.1145/3018661.3018731`](https://doi.org/10.1145/3018661.3018731). |

## Submission-order correction checklist

1. Fix `king2016dynamiccsr`; the current DOI is objectively unrelated.
2. Convert `vo2021shielddb` to the final 2023 TKDE record.
3. Re-scope the `:175-178` citation bundle so Bonawitz alone supports
   canceling masks and Cash/ShieldDB/Obladi support the earlier dynamic-system
   background.
4. Add a local CSSC citation to the pseudocode-audit paragraph.
5. Replace categorical “No” with “Not described” where non-support is inferred
   from scope rather than explicitly stated.
6. Re-check the dated SparseE public boundary immediately before submission.
7. Complete the page, issue, DOI, URL, and acceptance fields listed in P2-4.

After items 1–3, the citation layer is suitable for an expert manuscript review.
The remaining P2 work is copy-editing and qualification hardening; it does not
change the paper's current narrow contribution claim.

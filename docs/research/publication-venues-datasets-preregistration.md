# Publication venues, temporal datasets, and preregistration plan

Research checked: **2026-08-23 (Asia/Shanghai)**
Paper lane assessed: update-aware FHE sparse SpMV systems/methodology plus reproducible empirical characterization; no claimed new cryptographic primitive or formal-security result.

## Executive decision

1. **Primary target: Journal of Cryptographic Engineering (JCEN).** It has the cleanest scope match if the paper contains real OpenFHE measurements, end-to-end correctness evidence, a precise leakage/update contract, and an implementation-level explanation of why the update mechanism changes encrypted SpMV behavior.
2. **Performance-led backup: The Journal of Supercomputing.** Use this route if the strongest contribution is the causal performance characterization and calibrated systems methodology. A one-host simulator-only submission would be a substantial fit risk.
3. **Broad, continuous fallback: IEEE Access.** This is realistic for a reproducible negative/boundary result or broad systems methodology, but it is gold open access and requires a current APC budget.
4. **Security-led conditional target: International Journal of Information Security (IJIS).** Consider it only if the threat model, leakage claims, whole-query evidence, and security limitations are unusually strong. It is currently fully open access and therefore also requires an APC budget.

For publication-scale data, make **three real temporal sources** the primary corpus: Stack Overflow interactions, Simple English Wikipedia revisions, and NYC TLC yellow-taxi trips. Use **LDBC SNB Interactive v2 SF30 only as a controlled synthetic auxiliary corpus**, particularly for a natural-update lane containing explicit deletes. Do not pool LDBC with the real-source fixed-corpus primary decision.

The recommended full robustness panel is **3 datasets × 2 frozen semantics × 5 disjoint source partitions = 30 paired trace units**. Before publication-scale execution, the sole confirmatory family is frozen to T2 at 0.1 s freshness (15 paired units); the other three semantics-by-freshness families are prespecified secondary panels. The five units must differ in source entities/events, not merely in a random seed applied repeatedly to the same trace.

## Evidence policy and caveats

- Only publisher, society, project-owner, or data-owner pages are used below. Search-result snippets, journal-ranking sites, Wikipedia, Kaggle mirrors, and secondary venue lists are excluded.
- “SCIE” and “Ei Compendex” are reported only where the journal's official publisher page lists them. This report does **not** silently equate SCIE with the narrower historical label “SCI.”
- A live regular-submission portal with no posted closing date is reported as “no fixed regular deadline stated,” not as a guaranteed rolling call. Recheck every venue immediately before submission.
- License notes are research-planning guidance, not legal advice. Preserve attribution and provenance, avoid redistributing raw data unless the applicable terms are satisfied, and recheck terms when the acquisition manifest is frozen.

## Venue decision matrix

| Priority | Venue | Officially stated indexing | Submission model and format | Fit for this paper | Principal risk |
|---|---|---|---|---|---|
| 1 | [Journal of Cryptographic Engineering](https://link.springer.com/journal/13389) | SCIE; Ei Compendex | Hybrid; regular submission page is live and no fixed regular deadline is stated. Springer LaTeX source plus PDF is accepted/recommended; 150–250-word abstract and 4–6 keywords. No explicit regular-article page cap was found in the checked author instructions. | Direct match for implementations, architectures, tools, applications, and real-world evaluation in cryptographic engineering. | A scheduling/simulation paper without measured FHE operations, leakage boundaries, and correctness evidence will look too far from cryptographic engineering. |
| 2 | [The Journal of Supercomputing](https://link.springer.com/journal/11227) | SCIE; Ei Compendex | Hybrid; regular submission page is live and no fixed regular deadline is stated. LaTeX source plus PDF is recommended; 100–150-word abstract and 4–6 keywords. No explicit regular-article page cap was found. | Strong if the paper is organized around performance methods, systems behavior, resource trade-offs, and reproducible causal characterization. | “Supercomputing” reviewers may reject a single-machine or calibrated-simulator study that lacks credible scale, multi-platform measurements, or a convincing computational-systems contribution. |
| 3 | [IEEE Access](https://ieeeaccess.ieee.org/about/) | SCIE; Ei Compendex | Continuous publication and gold OA. Required double-column, single-spaced IEEE template. No hard page limit, but the journal recommends fewer than 20 pages and requires an editor-in-chief inquiry before submitting over 20 pages. | Broad enough for a carefully validated cross-disciplinary systems/methodology paper, including well-supported negative or applicability-boundary findings. | Current APC, a broad readership, and binary accept/reject review increase the cost of weak positioning or incomplete quantitative validation. |
| 4, conditional | [International Journal of Information Security](https://link.springer.com/journal/10207) | SCIE; Ei Compendex | Fully OA; regular submission page is live and no fixed regular deadline is stated. LaTeX two-column source plus PDF; 150–250-word abstract and 4–6 keywords. No explicit regular-article page cap was found. | Its scope includes applied cryptography, implementations, privacy, and system security. | The contribution may be judged insufficiently security-centered without formal novelty; the current full-OA APC is also a practical constraint. |

### Venue facts and current cost/status

#### 1. Journal of Cryptographic Engineering

- The official [aims and scope](https://link.springer.com/journal/13389/aims-and-scope) explicitly covers architectures, algorithms, techniques, tools, implementations, and applications in cryptographic engineering, including public-key cryptography and efficient software/hardware architectures.
- The official journal page lists both **Science Citation Index Expanded** and **Ei Compendex** under indexing.
- The current [publishing-options page](https://link.springer.com/journal/13389/how-to-publish-with-us) describes a hybrid model: open access currently lists **£2,590 / US$3,490 / €2,890**, while the subscription route states that no APC applies. Taxes and institutional agreements can change the amount.
- The checked [submission guidelines](https://link.springer.com/journal/13389/submission-guidelines) specify single-blind review, a 150--250-word abstract, 4--6 keywords, numeric citations, editable source at submission, and the Springer Nature LaTeX template in recommended `[iicol]` mode. They require a data-availability statement and state that an LLM cannot be an author; substantive generative-AI use should be documented as required by the publisher policy. No regular-article page or word cap appears in the checked instructions. Recheck the exact disclosure and formatting text at submission.
- **Frozen initial format/budget choice:** regular article, `[iicol]`, editable LaTeX plus PDF, an internal target of at most 18 two-column pages before supplementary material, and the subscription route unless the author or funder separately approves optional open access after acceptance. The publication-route choice carries no experiment or analysis authority.
- **Submission recommendation:** lead with the engineering mechanism and measured consequences, not a generic encrypted-computing application. Include OpenFHE/version/parameter manifests, byte-accurate traffic accounting, end-to-end correctness, update/leakage boundaries, and sensitivity outside the nominal operating point.

#### 2. The Journal of Supercomputing

- The official [aims and scope](https://link.springer.com/journal/11227/aims-and-scope) covers supercomputing technology, architecture and systems, algorithms and programs, performance measures and methods, and applications.
- The official journal page lists **Science Citation Index Expanded** and **Ei Compendex**.
- The current [publishing-options page](https://link.springer.com/journal/11227/how-to-publish-with-us) describes a hybrid model: open access currently lists **£2,590 / US$3,490 / €2,890**, while the subscription route states that no APC applies.
- The checked [submission guidelines](https://link.springer.com/journal/11227/submission-guidelines) provide the format expectations summarized in the matrix.
- **Submission recommendation:** choose this target only after adding credible backend measurements and scale evidence. Report where the calibrated model ceases to predict measured behavior; that boundary is a methodological contribution, not an embarrassment.

#### 3. IEEE Access

- The official [About page](https://ieeeaccess.ieee.org/about/) describes IEEE Access as multidisciplinary, continuously published, and fully open access.
- The official [bibliometrics page](https://ieeeaccess.ieee.org/about/bibliometrics/) lists both **Science Citation Index Expanded** and **Ei Compendex**.
- The current [APC page](https://ieeeaccess.ieee.org/about/article-processing-charges/) lists **US$2,160 plus applicable local taxes** and says there is no hard page limit, while recommending fewer than 20 pages.
- The official [submission guidelines](https://ieeeaccess.ieee.org/authors/submission-guidelines/) require the double-column IEEE template, quantitative validation appropriate to the work, and disclosure of AI-generated text in the acknowledgements under the journal's current policy.
- **Submission recommendation:** use the broader room to publish the preregistered boundary conditions, trace artifacts, and negative results. Do not treat broad scope as a lower evidence threshold.

#### 4. International Journal of Information Security

- The official [aims and scope](https://link.springer.com/journal/10207/aims-and-scope) includes computer security, applied cryptography, system and network security, privacy, and implementations/applications.
- The official journal page lists **Science Citation Index Expanded** and **Ei Compendex**.
- The current [publishing-options page](https://link.springer.com/journal/10207/how-to-publish-with-us) describes a fully open-access model and currently lists **£2,690 / US$3,690 / €2,990**. Taxes and agreements may alter the payable amount.
- The checked [submission guidelines](https://link.springer.com/journal/10207/submission-guidelines) provide the format expectations summarized above.
- **Submission recommendation:** do not manufacture a formal-security claim to fit the venue. A candid leakage contract, adversarial interpretation of RowMap visibility, and precise statement of what is and is not protected are prerequisites for this route.

### Deadline interpretation

IEEE Access explicitly states continuous publication. For the three Springer journals, the checked regular-submission pages are live and do not state a fixed closing date. That supports planning them as regular submissions, but it is not a promise that policies or availability cannot change. No special-issue deadline should drive this manuscript unless the eventual call's scope exactly matches the completed experiments.

## Dataset decision matrix

| Role | Official source and frozen release | License/provenance path | Event-to-matrix mapping | T1/T2 feasibility | Main risk |
|---|---|---|---|---|---|
| Primary real 1 | [Stanford SNAP Stack Overflow temporal network](https://snap.stanford.edu/data/sx-stackoverflow.html), frozen to the official a2q/c2q/c2a typed objects | The source page identifies Stack Exchange interactions; Stack Overflow's [public terms](https://stackoverflow.com/legal/terms-of-service/public) and [content-licensing help](https://stackoverflow.com/help/licensing) inform the recorded terms assessment, but their applicability to SNAP's derived typed files remains unresolved. | Directed user-to-user event `(answerer/commenter, question or answer owner, timestamp)` using the source object's official interaction type; type is retained as metadata, not mixed into the weight. | Repeated pairs create Modify under both semantics; expiry creates Delete under T2. | Historical posts span different CC BY-SA versions. Publish acquisition/transform code and hashes by default; do not casually redistribute the raw stream under a single invented license. |
| Primary real 2 | Wikimedia Analytics [MediaWiki History](https://dumps.wikimedia.org/other/mediawiki_history/readme.html), freeze [Simple English Wikipedia snapshot 2026-07](https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/2026-07.simplewiki.all-time.tsv.bz2) | The official Analytics readme dedicates all Analytics datasets to **CC0**. The exact all-history Bzip2 TSV object was listed as 985,335,238 bytes when checked; compute and publish a local SHA-256 because its directory does not list a publisher checksum. | Directed bipartite event `(namespace-0 page ID, permanent contributor ID, revision timestamp)` using revision-create events. | Re-edits create Modify; window expiry creates Delete. | The complete monthly snapshot can revise reconstructed historical metadata, so the exact snapshot/object hash is part of the experiment. Exclude anonymous/temporary contributors by frozen fields rather than handling IP-like identities. |
| Primary real 3 | [NYC TLC Trip Record Data](https://www.nyc.gov/site/tlc/about/tlc-trip-record-data.page), freeze the 12 monthly 2022 yellow-taxi Parquet objects | NYC's [Open Data FAQ](https://opendata.cityofnewyork.us/faq/) describes reuse, and the city's [technical standards/policies](https://cityofnewyork.github.io/opendatatsm/publicpolicies.html) describe open publication without registration, license, or usage restrictions unless a dataset-specific condition applies. | Directed time-expanded OD event: row `(pickup zone, pickup 15-minute bin of week)`, column `(drop-off zone, drop-off 15-minute bin of week)`, ordered by pickup time. Use the official [yellow-taxi dictionary](https://www.nyc.gov/assets/tlc/downloads/pdf/data_dictionary_trip_records_yellow.pdf). | Recurrent weekly OD-bin pairs create Modify; expiry creates Delete. | The time-expanded graph is a declared derived sparse matrix, not a graph supplied by TLC. Filter invalid zones and impossible times without outcome-dependent tuning. |
| Auxiliary synthetic | [LDBC SNB datasets](https://ldbcouncil.org/benchmarks/snb/datasets/) and official [Interactive v2 update archives](https://ldbcouncil.org/data-sets-surf-repository/surf/snb-interactive-v2-updates.html), freeze the matching SF30 snapshot and `interactive-updates-sf30.tar.zst` plus exact object hashes | LDBC's official [documentation](https://ldbcouncil.org/ldbc_snb_docs/) states the specification's CC BY 4.0 terms; its project-owned [data-generator](https://github.com/ldbc/ldbc_snb_datagen_spark) and [Interactive v2 implementations](https://github.com/ldbc/ldbc_snb_interactive_v2_impls) expose their software licenses. Preserve release and generator provenance, and confirm any archive-specific redistribution terms before republishing the downloaded objects. | For a natural-update D0 lane, use friendship `INS8` and `DEL8` on person-person adjacency; for comparable T1/T2 lanes, replay only friendship creation events through the same frozen transforms used for real data. | Native inserts/deletes are available for D0; T1/T2 are also feasible from creation events. | Interactive v2 documentation is marked work in progress, and the corpus is synthetic. Never describe this as an audited LDBC benchmark result or pool it with the real-data fixed-corpus primary analysis. |

### Dataset-specific extraction rules

#### Stack Overflow

The official SNAP page reports a large chronological interaction stream with repeated directed pairs, which is particularly useful for distinguishing Insert from Modify. Freeze the **typed union** before inspecting performance: download and merge the three official objects `sx-stackoverflow-a2q.txt.gz`, `sx-stackoverflow-c2q.txt.gz`, and `sx-stackoverflow-c2a.txt.gz`, assigning the object identity as the auxiliary interaction-type field. Do not use only `sx-stackoverflow.txt.gz`: that union object contains `SRC DST UNIXTS` but no per-record type, so the declared type-preserving transform cannot be reconstructed from it.

Use source and target user identifiers as row and column identities. Drop self-loops under one global rule and report their count. Order by `(normalized UTC timestamp, source-file ordinal, within-file ordinal)` so equal-second events within and across files remain deterministic.

Because Stack Exchange content-license terms changed historically, the artifact should contain the downloader, source URL, retrieval metadata, parser, derived trace hashes, and attribution file. Redistribute the raw SNAP file only after confirming all applicable terms; reproducibility-by-download is the safer default.

#### Simple English Wikipedia

Use the exact `2026-07.simplewiki.all-time.tsv.bz2` Wikimedia Analytics object URL observed in the official versioned directory, never a moving alias. The publisher does not promise permanent retention or immutability, so acquisition records its local SHA-256. The official [MediaWiki History schema](https://wikitech.wikimedia.org/wiki/Analytics/Data_Lake/Edits/Mediawiki_history_dumps) documents a full revision, user, and page history without article text. It also warns that each monthly full snapshot may reconstruct older records differently after later renames, moves, reverts, or log changes; that makes the exact snapshot and local SHA-256 scientifically material.

Keep only `event_entity = revision`, `event_type = create`, historical namespace 0, non-null stable page IDs, valid event timestamps, and contributors whose frozen record says they are permanent. Drop anonymous/temporary identities rather than processing their historical text. Permanent contributors include bots; the canonical trace does not preserve a bot label, so this experiment makes no bot-specific sensitivity claim.

Map article page ID to row and permanent contributor ID to column. Page-as-row permits five disjoint page partitions at the required 4,096-row size: the official project page reports roughly [284,000 articles and 10.9 million edits](https://meta.wikimedia.org/wiki/Simple_English_Wikipedia) at the checked time. This is explicitly a temporal **bipartite article–editor sparse matrix**, not a social graph.

#### NYC TLC 2022 yellow taxi

Freeze all twelve official monthly 2022 Parquet objects and the unversioned official taxi-zone lookup as accessed on 2026-08-23. Do not call that later-updated lookup contemporaneous with 2022. Record each URL, byte count, retrieval timestamp, response metadata, and local SHA-256. Apply only the outcome-independent validity rules frozen here: non-null pickup/drop-off timestamps, `dropoff >= pickup`, and valid pickup/drop-off location IDs in the official lookup. The pickup wall clock must belong to the year/month named by its `yellow-2022-MM` source role; drop-off may cross the month boundary. Interpret naive clocks in `America/New_York`, choose the first occurrence (`fold=0`) for a fall-back ambiguity, and reject/count a spring-forward wall time that does not survive a local→UTC→local round trip.

The 15-minute bin-of-week expansion gives up to `263 × 672 = 176,736` possible identities on each side before observed-data filtering, which is ample for a frozen `4096 × 8193` submatrix while retaining repeated weekly coordinates. The mapping is directed and uses pickup time as the event time. No fare, payment, passenger-count, or vendor field enters the experiment.

#### LDBC SNB Interactive v2

The official [insert-operation specification](https://ldbcouncil.org/ldbc_snb_docs/workload-inserts.pdf) defines `INS8` friendship creation, and the official [delete-operation specification](https://ldbcouncil.org/ldbc_snb_docs/workload-deletes.pdf) defines `DEL8` friendship removal. These form a useful natural-update control because deletes are not synthesized by window expiration.

Freeze the matching SF30 initial snapshot, `interactive-updates-sf30.tar.zst`, both exact downloadable-object digests, relevant specification version, parser commit, and—if regeneration occurs—the generator commit and container digest. Canonicalize the undirected friendship pair once. If the SpMV representation requires directed adjacency, emit both directed entries atomically and state that expansion in the trace manifest.

Keep the following lanes separate:

- **D0 natural-update auxiliary:** apply official `INS8`/`DEL8` operations.
- **T1/T2 auxiliary comparability:** ignore official deletes and derive both semantics from creation-event arrivals exactly as for the three real sources.

Only the three real-source T1/T2 lanes enter the fixed-corpus primary decision.

## Exact T1/T2 transform

The following frozen transform keeps the manuscript's fixed coefficient bound `|A[i,j]| <= 7` and makes insert/modify/delete labels deterministic.

Let `N_uv(t)` be the number of accepted events for coordinate `(u,v)` in the active history at logical time `t`. Define:

```text
A_uv(t) = min(7, N_uv(t))
```

All weights are non-negative integers; the absolute-value bound therefore holds.

### T1: cumulative first-occurrence/repeat semantics

- Active history is all accepted events up to `t`.
- `0 -> 1` is **Insert**.
- `k -> min(7, k+1)` for `k > 0` is **Modify** only if the visible coefficient changes.
- Once the coefficient is 7, further repeats are logged as **clipped no-ops** and do not become fake modifications.
- T1 has no deletes.

### T2: fixed-event-count sliding window

- Freeze window size **`K = 32,768` accepted raw events** for every dataset and partition. This is an event-window adjacency, not a claim about equal historical wall-clock duration.
- For each incoming event, expire the oldest event first if admission would make the queue exceed `K`, then admit the new event.
- Expiry changes `1 -> 0` as **Delete** and `k -> k-1` as **Modify**, subject to the same clipping rule. Admission changes `0 -> 1` as **Insert** and a changing nonzero value as **Modify**.
- Expiry and admission are distinct logical transitions in the incoming event's
  accepted-event group, ordered by `transition_ordinal` with expiry before
  admission. Each record separates the incoming `trigger_event` identity from
  the affected `subject_event` identity; for expiry, the subject is the oldest
  raw event removed from the window. This also resolves the case in which both
  transitions affect the same coordinate.
- A transition hidden by coefficient clipping is a logged no-op, not a logical update.

For both semantics, order raw events by `(normalized UTC timestamp, source-file ordinal, within-file ordinal)`. Do not use nondeterministic dataframe ordering. Keep source time for provenance but drive the systems replay with a separate, fixed logical arrival clock; historical multi-year gaps must not be interpreted as seconds available to the online system.

## Publication-scale sampling plan

### Frozen universe selection

For each real dataset:

1. Let `V` be the number of events in the closed, canonical, chronological schema-valid corpus. Reserve exactly event ordinals `[0, floor(V/10))` as the structure-only mapping prefix. It is not part of the evaluated 10/30/60 split.
2. Assign each source identity to one of five disjoint partitions with `SHA256(dataset_release || canonical_source_id) mod 5`.
3. Within each partition, rank source identities by prefix event count, breaking ties by canonical ID, and select 4,096 rows.
4. Conditional on those rows, rank target identities by prefix event count, breaking ties by canonical ID, and select up to 8,193 observed columns. If fewer exist, fill the remaining positions with deterministic reserved empty IDs; padding above 10% makes the unit ineligible.
5. Apply that frozen mapping to the remaining 90% of the chronological stream. Events outside the selected rectangle are rejected and counted.

Source partitioning makes the five trace units event-disjoint on the row side. Target identities may overlap, but no source event can appear in two units. If a partition lacks enough qualifying identities, the dataset fails the preregistered eligibility rule; do not silently substitute a denser period after seeing performance.

### Trace length and eligibility

- Target **131,072 accepted raw events per dataset × partition × semantics** after the mapping prefix.
- Require at least **65,536 emitted logical changes** and a conservative
  rho/freshness-independent lower bound of **1,000 complete publication
  windows**; every cell separately reports its realized window count.
- Freeze a group-atomic microbatch threshold of `64` visible SET transitions
  (T1 windows contain at most 64; a two-transition T2 group may complete at 65)
  and preserve the manuscript's `4096 × 8193` matrix shape, maximum row nonzeros
  `4,096`, coefficient bound 7, cryptographic parameters, and candidate set.
- A coverage-based schema-validity/resource pilot must use exactly the first
  `floor(V/10)` events of each closed canonical schema-valid corpus, where `V`
  is that corpus's full schema-valid event count. It covers the exact Cartesian
  product of the three real datasets, `{T1,T2}`, and partitions
  `{0,1,2,3,4}`. A preliminary suffix scan is allowed only to establish `V` and
  validate canonical order; mapping, transform, and serialization logic may not
  consume a suffix event.
- The pilot may report only aggregate structure/cardinality and eligibility,
  completion, parser/adapter error codes, elapsed time, process-high-water peak
  resident memory, live-coordinate cardinality, runtime health, and canonical
  round-trip completeness for prefix-derived structural records. Only aggregate
  serialization counts and bytes may be reported; no transition payload artifact
  may be retained. It
  emits exactly `structure-pilot-report.json` and `checksums.sha256`, with no raw
  identities or mapping table.
- The pilot may not import or exercise the publication schedule or Day1B
  producer, dispatch candidates, or compute, log, display, or retain candidate
  identities/configuration, operation or communication costs, effects, ranks,
  Pareto/dominance results, rho/freshness, query material or results,
  cryptographic outputs, or held-out/confirmatory classifications. It mints no
  evidence role, authority, anchor, or compatibility receipt. Both files are
  pre-freeze, permanently non-admissible, non-promotable, and outside every
  Publication Evidence Lineage.
- Canonical events stream to one per-dataset disk-backed SQLite store, which is
  closed and deleted before the next dataset. Prefix mapping is aggregated in
  SQLite and transformation streams into a transient counting/round-trip sink;
  the pilot retains no full corpus, prefix-event collection, transition-record
  collection, or serialized-chunk collection in Python memory. T2 live state is
  bounded by `K`; the T1 live-coordinate maximum is reported as an observed
  aggregate.
- `process_high_water_rss_bytes_before_report_install` is process-lifetime
  `ru_maxrss` sampled after final input/source revalidation and scratch teardown,
  immediately before report installation. `analysis_wall_clock_ns` spans from
  immediately before the exclusive scratch claim through that checkpoint.
  Report validation/serialization, checksum construction, staging writes and
  `fsync`, and atomic installation are outside both measurements. Dataset/cell
  RSS values remain cumulative completion checkpoints, not attributable
  increments. `canonical_store_bytes_after_index` is only the
  main SQLite file size at the post-index checkpoint and excludes source
  snapshots, SQLite temp/query files, filesystem allocation, and other
  transient scratch. It is not a scratch peak and cannot alone freeze a
  scratch cap. `prefix_transition_serialized_bytes` is cumulative transient
  canonical byte volume, not retained output.
- The report binds each dataset to the verified acquisition transaction,
  source-set, and central acquisition Behavior Set digests and their derived
  binding digest. It records the SQLite library version and verifies
  `temp_store=FILE`. Production additionally requires one workflow-fixed,
  pre-provisioned external scratch root that is absolute/canonical,
  current-user-owned, mode `0700`, writable, empty and exclusively claimed,
  and disjoint from the repository, acquisition, and output trees. The closed
  scratch-root environment, `TMPDIR`, `SQLITE_TMPDIR`, and Python's cached
  temporary root must name that exact path before execution. The core pins its
  device/inode, creates a unique child workspace for the per-dataset stores,
  and requires inode-owned, empty-only teardown. A replaced store,
  source-snapshot, or directory is preserved and causes a global `HOLD` rather
  than recursive pathname cleanup. The report binds only the scratch policy
  and a path/device/inode-derived identity; it does not report scratch occupancy.
- SQLite below 3.35, any compile option other than the single frozen
  `TEMP_STORE=1`, or failure to read back FILE policy is a
  global no-write `HOLD`. Environment binding states where FILE-policy
  temporary work is requested, not a proof of SQLite's effective physical
  temporary directory or byte occupancy; small structures may remain in page
  cache. Expected parser/canonical-store failures use only `parser-failed` or
  `canonical-scan-failed` and retain ten blocked cells; authority, source,
  safety, or binding drift produces a global no-write `HOLD`.

The resulting full-panel design has:

```text
3 real datasets × 2 semantics × 5 disjoint source partitions = 30 paired units
```

LDBC produces an auxiliary D0/T1/T2 panel reported separately. Repeated query-vector or cryptographic seeds on one event trace are repeated measurements, **not independent sample units**.

### Replay and held-out split

- Freeze one logical accepted-arrival rate at **128 accepted raw events/s**, and use it for every real dataset. Preserve raw-event order. This decouples systems freshness from arbitrary historical silence in source clocks.
- Treat freshness windows as half-open: before a group at logical time `t`,
  close any pending window whose deadline is `<= t`; the boundary group belongs
  to the next window and remains atomic in SET→TICK→query order.
- Freeze `T2 × 0.1 s` as the sole confirmatory family. Retain T1 and `1.0 s` as prespecified secondary robustness panels. A `10 s` panel is not currently authorized; it requires a separately frozen pre-execution descriptive protocol.
- Freeze bandwidth at `1,000 Mb/s` for primary analyses. The `100` and `10,000 Mb/s` panels are not currently authorized; either requires a separately frozen pre-execution descriptive protocol.
- Partition accepted raw-event groups, not realized Publication Windows, into
  common half-open ordinal ranges **10% warm-up / 30% tuning / 60% held-out**
  using floor boundaries at `N/10` and `4N/10`. Force an atomic window closure
  at each boundary, and carry state continuously without reset. Every
  freshness/rho cell for one trace uses the same raw-event ranges.
- Use the same trace and queries for all 14 candidate records. Candidate identity, schedule, and policy must not affect which raw events are admitted.
- Freeze one length-8193 bound-one ternary query vector per paired unit with
  seed `2026082302`; force coordinates 0 and 8192 to +1 and -1, respectively,
  and reuse it across every cell/candidate in that unit. This is a deterministic
  public known-answer evaluation control, not a natural-query-distribution
  sample, security-randomness source, or query-confidentiality test.
- Keep query-vector seed `2026082302`, partition/calibration-resampling seed
  `2026082301`, and cryptographic randomness in separate manifest fields.

No smaller fallback tier is currently authorized. In particular, 65,536 raw
events is invalid for T2 because the 40% tuning boundary precedes the first
expiry at `K=32,768`. If the target is infeasible in a prefix-only pilot, stop
before held-out work and preregister one common replacement satisfying
`floor(N/10) <= K < floor(4N/10)`; never choose a tier per dataset or from
observed candidate outcomes.

Exact wall-clock, resident-memory, scratch/output-byte, shard, concurrency,
preemption, and retry limits remain `PENDING-FREEZE` until the structure-only
`floor(V/10)` prefix feasibility pilot. The reviewed, outcome-independent
amendment must be committed before the clean pre-anchor `S1` and before held-out
work, then applied uniformly. Candidate timeout/resource failure receives no retry; a
separately diagnosed infrastructure preemption invalidates the whole shard and
permits at most one identical whole-shard rerun.
The post-index SQLite file checkpoint is insufficient by itself to freeze the
scratch limit; the amendment must add a separately reviewed controlled-scratch
high-water measurement or keep execution on `HOLD`.

## Paired analysis unit and preregistered fixed-corpus decision

### Primary estimand

The paired unit is one `(dataset, semantics, source partition)` trace. The
confirmatory finite corpus is the 15 T2 units at 0.1 s. Within a trace, compare
candidates pairwise on the identical windows, queries, parameters, and network
assumptions.

Report, at minimum:

- every unit-level paired effect, not only an aggregate;
- median, interquartile range, and a descriptive partition-weighting interval
  for each primary paired contrast;
- results stratified by dataset and by T1/T2;
- Insert/Modify/Delete/clipped-no-op proportions and realized row-density distributions;
- prespecified descriptive calibration residuals, if a direct held-out component
  target and residual formula are frozen before measurement; no prediction-
  accuracy threshold or pass claim is currently authorized;
- failures, timeouts, infeasible candidates, and missing windows as outcomes rather than silently dropping them.

Use **10,000 dataset-stratified source-partition resamples**, never resampling
individual windows as if independent, and freeze seed `2026082301`. The central
95% interval is a descriptive sensitivity to partition weighting, not a
confidence interval. The deterministic partitions are not independent
population draws, so no sign test, p-value, Holm adjustment, or cross-dataset
population inference is authorized.

Keep the frozen practical rule in the sole confirmatory family: at least **15%
paired-median improvement**, all 15 fixed-unit effects strictly positive, and
all 15 selected points non-dominated at **two adjacent prespecified rho grid
points**. Report every one of the nine points. Secondary panels remain complete
robustness reports but have no positive or negative headline authority beyond
the conservative completeness veto.

### Mandatory negative-result rule

If the method is not non-dominated, misses the 15% threshold, or wins only in a single isolated regime, report the boundary result. Do not relabel the primary outcome as an ablation or promote an unregistered sensitivity analysis. This outcome-independent rule keeps a methodology/characterization paper defensible even when the headline is negative.

## Acquisition and reproducibility manifest

For every raw object and every derived trace, record:

- dataset/release name and exact source URL (without claiming publisher immutability);
- UTC retrieval time, byte count, HTTP `ETag` and `Last-Modified` when supplied;
- final URL, status, normalized media type, and a digest-bound downloader
  request/response receipt; a caller-written local manifest is not acquisition
  authority;
- publisher checksum where supplied and local SHA-256 in all cases;
- each applicable license/terms page's no-fragment fetch URL, section anchor,
  retrieval UTC, optional response validators, byte count, local SHA-256,
  attribution text, and redistribution decision;
- parser version/commit, container/runtime digest, locale, timezone, and timestamp parser;
- every filter and its rejected-event count;
- source/target mapping hash and canonical-ID serialization;
- raw accepted-event hash, T1 trace hash, T2 trace hash, and event-type counts;
- matrix shape, realized row-nonzero maxima, coefficient extrema, and bound violations;
- all query/statistical seeds and the cryptographic RNG policy, recorded separately;
- OpenFHE version/commit, compiler, flags, CPU/OS, thread affinity, and protocol parameters.

Publish scripts, manifests, checksums, and derived traces when licensing permits. For share-alike or ambiguous redistribution cases, publish a deterministic reproduce-by-download workflow and derived hashes instead of copying the raw corpus into the artifact.

## Pre-submission gates by venue

### Gate common to all four venues

- At least three real sources and 30 preregistered trace units under the frozen plan, paired across T1/T2 by source partition; do not describe all 30 as mutually independent.
- Real OpenFHE backend measurements for every primitive used by the calibrated model, plus prespecified descriptive residuals against any separately frozen held-out component target and end-to-end correctness checks.
- Exact leakage/update contract, including RowMap visibility and what deletion/modification patterns reveal.
- Byte-accurate communication accounting and wall-clock measurements with uncertainty.
- Reproduction manifest, environment lock, raw/derived hashes, and license-aware artifact instructions.
- Explicit generative-AI disclosure following the selected journal's policy; human authors remain accountable for sources, claims, code, and prose.

### Additional target-specific gate

- **JCEN:** cryptographic-engineering mechanism and implementation evidence are central, not a wrapper around a generic simulator.
- **Journal of Supercomputing:** credible scale/platform diversity or a strong explanation of why the measured system represents supercomputing behavior.
- **IEEE Access:** APC approval, fewer than 20 pages unless the editor-in-chief approves otherwise, and a narrative accessible beyond cryptographic engineering.
- **IJIS:** security-centered threat/leakage analysis strong enough that absence of formal crypto novelty is an explicit boundary rather than a hidden weakness.

## Final recommendation

Freeze **JCEN as target A** and **The Journal of Supercomputing as target B** now. Keep IEEE Access as the publication-resilient fallback for a strong reproducible boundary result. Treat IJIS as conditional on the security analysis becoming a genuine co-equal contribution.

Freeze the three-real-dataset corpus, the 30-unit full panel, and the sole 15-unit T2-at-0.1-s confirmatory family before looking at held-out performance. Add LDBC SF30 only as a separately labeled synthetic/natural-delete auxiliary panel. This combination gives the paper three complementary real structures—social interaction, bipartite edit activity, and time-expanded mobility—while preserving exact, deterministic T1/T2 semantics and avoiding the false replication that would result from counting random reruns of one trace as independent evidence.

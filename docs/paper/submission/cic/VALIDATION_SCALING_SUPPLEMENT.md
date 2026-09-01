# Anonymous evidence and validation-scaling supplement

Status: anonymous circulation supplement for the current-source submission
candidate. Exact repository, commit, workflow-run, provider-artifact, and
account identifiers are retained in the private claim ledger and are omitted
here for double-blind review.

## 1. Evidence boundary and blinded chronology

The primary performance lineage passed exact-source CI, pinned-runtime smoke,
registration, and source/evidence compatibility controls. Its sole
qualification attempt crossed the frozen 45-minute computational threshold
while independent replay was still running and before the combined guard. The
attempt was cancelled. Its only retained object was a one-day producer-to-
replay handoff that was permanently marked non-evidence. No acquisition,
formal shard, terminal admission, aggregate, or analysis object exists.

A separately preregistered follow-up passed five fresh authority-false controls.
Its sole provider attempt stopped during hosted-runner setup, before source
checkout, seed admission, scientific execution, or artifact creation. The
one-shot rule prohibits a replacement attempt. Neither stopped lineage supports
strategy costs, a winner, speedup, native-resource measurements, or deployment
performance.

A distinct current-source conformance replication subsequently passed its
prespecified eight-case, 35-record deterministic contract and one fixed pinned-
OpenFHE whole-query witness. That result is limited to the exact fixture and
source and is not a performance or general-correctness result.

Finally, the separately preregistered validation-scaling study used one tagged
source and exactly one workflow attempt. It produced three private producer
handoffs, three redacted independent-replay packages, and one aggregate. All
seven jobs and all seven registered artifacts closed successfully. A separate
post-terminal process rehashed the six provider ZIPs, re-inspected all seed
packages, regenerated the aggregate, and required byte equality with the
provider aggregate.

## 2. Registered matrix and admissibility checks

The matrix crossed three fixed paths, three query counts, three deterministic
seed ordinals, and two roles:

- PR-1: `periodic-repack/windows=1`;
- Pad: `padding-reuse`;
- Seg-128: `packed-coo-cloud-segmented-delta/segment-width=128`;
- query counts: `Q = 5, 51, 512`, corresponding to
  `rho = 1/100, 1/10, 1`;
- roles: producer (P) and independent replay (R); and
- seed ordinals: 1, 2, and 3.

All 54 cells passed the frozen compile-call gate. The observed pairs were
`(Q,C) = (5,10), (51,102), (512,1024)`. All 27 replay cells were byte-equal to
the frozen semantic projection of their bound producer cells. There were no
failed jobs, retries, replacement seeds, incomplete cells, or extra workflow
attempts.

## 3. Exact operation observations

Nanosecond observations appear in frozen seed-ordinal order 1/2/3. Operation
clocks surround only the deep operation call; provider queue, environment
setup, trace generation, and artifact transport are excluded.

| Path | Role | Q | Wall observations (ns; seeds 1/2/3) | Process observations (ns; seeds 1/2/3) |
|---|---:|---:|---|---|
| PR-1 | P | 5 | 493779430, 532934089, 507080142 | 483951906, 521703002, 500793415 |
| PR-1 | P | 51 | 3248320990, 3477269717, 3300070577 | 3181972560, 3402008544, 3237905668 |
| PR-1 | P | 512 | 32915028304, 35867964129, 32545396098 | 31478582209, 35077433935, 31888696879 |
| PR-1 | R | 5 | 535495225, 463262803, 543910110 | 531559242, 463188826, 543870282 |
| PR-1 | R | 51 | 3491820676, 2983633320, 3514566690 | 3491371009, 2983272235, 3512252293 |
| PR-1 | R | 512 | 34046458161, 29166683091, 34302023457 | 34042683754, 29162610198, 34295698918 |
| Pad | P | 5 | 473907071, 487044758, 485985592 | 467007561, 478747039, 478796169 |
| Pad | P | 51 | 3040031399, 3214256944, 3085047603 | 2972852191, 3123193713, 3016533741 |
| Pad | P | 512 | 29680951160, 31403117207, 29918150801 | 28979503184, 30561346033, 29271529873 |
| Pad | R | 5 | 503717776, 434565424, 504804973 | 503672641, 434556797, 504699279 |
| Pad | R | 51 | 3247204005, 2823045791, 3169356688 | 3246876817, 2820185656, 3168861055 |
| Pad | R | 512 | 30842827988, 26838917363, 30980486190 | 30839844499, 26836489662, 30973526629 |
| Seg-128 | P | 5 | 975892069, 1045922899, 1013790378 | 965094550, 1034049140, 1002793496 |
| Seg-128 | P | 51 | 6882735836, 7357727101, 7093630442 | 6783658499, 7226826775, 6985623144 |
| Seg-128 | P | 512 | 67588683872, 71420420925, 69763297981 | 66568054413, 70076982717, 68507886069 |
| Seg-128 | R | 5 | 1054320382, 975760879, 1127400353 | 1054235604, 975674523, 1127216861 |
| Seg-128 | R | 51 | 7527417093, 6863896668, 7928797909 | 7525894004, 6863148242, 7927742507 |
| Seg-128 | R | 512 | 73518473351, 66059875768, 77085576268 | 73510372947, 66053368201, 77070873375 |

## 4. Producer stage observations

| Path | Q | State-transition ns (seeds 1/2/3) | Result-assembly ns | Cell-archive wall ns | Cell-archive process ns |
|---|---:|---|---|---|---|
| PR-1 | 5 | 226799500, 244331137, 244087473 | 203891584, 222113925, 203694397 | 470882, 450030, 499964 | 471078, 450138, 500263 |
| PR-1 | 51 | 1056331403, 1153911617, 1116823277 | 2057441223, 2177872541, 2048179919 | 1926728, 1373734, 1206222 | 1927041, 1373559, 1206069 |
| PR-1 | 512 | 10397125725, 11885115780, 10990793142 | 21552949500, 22940587766, 20594646766 | 12455472, 9850090, 13223308 | 12455944, 9851933, 13223876 |
| Pad | 5 | 206608704, 217178700, 216779375 | 202814095, 207836008, 209958771 | 421260, 462132, 392372 | 421215, 462271, 392231 |
| Pad | 51 | 873140630, 953655074, 917535279 | 2030926122, 2112355584, 2033823362 | 1115269, 2150759, 1183660 | 1115508, 2151027, 1183827 |
| Pad | 512 | 8182599050, 8975774444, 8612149977 | 20536455887, 21377519240, 20351905165 | 10914712, 13595827, 9339889 | 10915002, 13597911, 9340405 |
| Seg-128 | 5 | 301024905, 325526825, 306540936 | 597473639, 638500452, 623056942 | 897180, 1005458, 931308 | 897182, 1004952, 931447 |
| Seg-128 | 51 | 1000030923, 1099220335, 1025313514 | 5577035022, 5930443582, 5764367561 | 5508286, 6264881, 6317365 | 5508586, 6265973, 6317569 |
| Seg-128 | 512 | 8601286614, 9322065037, 8764897241 | 56367489378, 59346788626, 58347543025 | 81586371, 82364479, 87243124 | 81577002, 82366307, 87237072 |

## 5. Independent-replay stage observations

| Path | Q | Independent-replay elapsed ns (seeds 1/2/3) |
|---|---:|---|
| PR-1 | 5 | 535131785, 462950770, 543574934 |
| PR-1 | 51 | 3491331089, 2983241278, 3514130010 |
| PR-1 | 512 | 34045332735, 29165598745, 34300872148 |
| Pad | 5 | 503375366, 434235406, 504475565 |
| Pad | 51 | 3246765123, 2822616592, 3168934380 |
| Pad | 512 | 30841691741, 26837815021, 30979340781 |
| Seg-128 | 5 | 1053946072, 975426193, 1127031577 |
| Seg-128 | 51 | 7526957232, 6863433117, 7928341469 |
| Seg-128 | 512 | 73517295798, 66058761103, 77084460643 |

## 6. Exact-rational three-point fits

For each path and role, unweighted ordinary least squares fits the three median
wall observations to `T(Q) = alpha + beta Q`. Fractions below are reduced and
remain in nanosecond units. The intercept is extrapolated and is not an
observed fixed cost. No fit has a pass threshold.

| Path | Role | alpha (ns) | beta (ns/query) | R-squared |
|---|---:|---|---|---|
| PR-1 | P | 26838958292915/235843 | 30211802790291/471686 | 304251009279811684441288227/304256592278247672845806876 |
| PR-1 | R | 38433257032498/235843 | 31211737059883/471686 | 974172530295273897127973689/974177986669664910786105292 |
| Pad | P | 37753222616160/235843 | 27411725187747/471686 | 250467559256187767466312003/250468866451785068548153372 |
| Pad | R | 37973572518004/235843 | 14131009268368/235843 | 12480338933918894915336464/12480430180178629242129187 |
| Seg-128 | P | 60589749990449/235843 | 32013194866572/235843 | 341614881855037284294343728/341616481792529494809979753 |
| Seg-128 | R | 68137993060350/235843 | 67458964938927/471686 | 1516903983543794088279970443/1516906634867297005550755852 |

Nine-decimal second renderings of the median [minimum, maximum] summaries are
tabulated above. Table 5 of the manuscript and its surrounding text give the
compact three-decimal summaries used in the paper. The fitted slopes span
0.058114350--0.143016678 seconds/query; descriptive R-squared values span
0.999981650--0.999998252.

## 7. Claim-to-evidence mapping

| Claim | Released scope | Permanent exclusion |
|---|---|---|
| VS-C1 | All 27 replay cells matched their bound producer semantic projections at the exact reviewed source. | General correctness, other sources, other workloads, or adversarial security. |
| VS-C2 | All 54 cells satisfied the frozen compile-call bound with the observed pairs above. | An asymptotic complexity proof or an implementation-independent bound. |
| VS-C3 | The exact hosted-runner lifecycle observations and three-point descriptive fits are reportable. | Population inference, confidence claims, asymptotic extrapolation, or provider-queue performance. |
| VS-C4 | Producer and independent-replay stage observations are separately reportable. | A controlled producer/replay speedup comparison, since roles ran in distinct jobs. |

No row authorizes strategy superiority, a winner, pairwise speedup, native
OpenFHE performance, network/deployment performance, qualification GO,
reopening either stopped campaign, formal security, or universal correctness.
The authority-false aggregate boundary is intentional: this study can release
only the validation-scaling observations listed above.

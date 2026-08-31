# Current-source E4 conformance replication preregistration

Date: 2026-08-31 (Asia/Shanghai)

State: **frozen before dispatch; no result has been observed for the reviewed
current source**

Machine plan:
[`config/current-source-e4-conformance-study.json`](../../config/current-source-e4-conformance-study.json)

## 1. Purpose and scientific question

This is a narrow deterministic replication, not a third performance study.  Its
sole question is:

> At the exact reviewed current source, does the prespecified deterministic
> property-contract corpus pass, and does one fixed real OpenFHE BFVRNS
> CSSC-base-plus-strong-delta whole-query fixture decrypt to the prespecified
> sparse vector while matching both independent plaintext oracles?

The estimand is the exact Boolean/vector conformance outcome for one source
identity, eight deterministic cases, 35 contract records, and one fixed
4096-by-8193 encrypted fixture.  There is no runtime, resource, ranking,
speedup, cost, or population estimand.

## 2. Relation to the two terminal performance NO-GOs

The complete predecessor chain is retained:

1. Primary Route A performance qualification run `33261434612` reached its
   frozen deadline without the required qualification closure and is terminal
   NO-GO.  It minted no formal authority.
2. The separately preregistered follow-up performance run `33348855548` became
   terminal NO-GO under its one-shot rule before checkout, seed admission, or
   artifact creation.  It also minted no formal authority.

This replication neither reopens nor continues either lineage.  It does not
reuse either performance estimand, threshold, partial handoff, or stopped run.
The outcome-informed change is disclosed plainly: after both performance
routes closed, the paper was narrowed to protocol, source-conformance, and
fail-closed evidence-boundary claims.  The present study asks only whether the
already existing deterministic E4 witness still conforms at the final current
source.

The complete pre-study provider inventory for this workflow ID/path contains
two runs, both successful and both disclosed here.  They did not use
byte-identical workflow/witness specifications:

- source `fbd9712fc15e687489a58655b6e5faa7a7e43ec3`, run `32567669739`,
  artifact ID `9474520924`, provider digest
  `sha256:010997ec7afdff79dd894044304f05eedfe4d0d9b584f7dcc49cf87ddb858aaa`;
  this earlier specification produced sparse output
  `[(0, 123), (4095, 20)]`;
- the later historical evidence anchor at source
  `fcb00e0d7f111f3ab5003c111b124df83ae11813`, run `32581653504`, artifact
  ID `9477963854`, provider digest
  `sha256:c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`;
  by this later anchor, the present fixed specification and sparse output
  `[(0, 128), (4095, 5)]` were in place.  Between the two runs, fixed-query
  values at columns 1, 7, and 8192 changed respectively from `2` to `1`, `4`
  to `1`, and `-3` to `-1`.

Both historical outcomes are known and are not presented as fresh discoveries.
Since the later anchored witness, nine provenance-listed property/runtime
sources have changed, including the property producer and validator,
CSSC/event/ledger/query/state logic, strong execution, and their contract tests.
The result at the current source has not been run or observed.  From the later
`fcb00e0d7f111f3ab5003c111b124df83ae11813` anchor forward, the current fixed
seed, cases, workflow, witness, OpenFHE pin, expected vector, and pass criteria
have not changed.

## 3. Immutable source and review binding

The study source is the exact candidate commit reviewed by both ChatGPT Pro and
ZCode and then named by the immutable tag
`current-source-e4-conformance-20260831-v1`.  The commit is not embedded inside
its own files; the external-review record and tag bind it without a self-hash
cycle.  Before dispatch, the controller must verify all of the following:

- the candidate has sole parent `187347f80ad4333749528229891bd65b8f3a518b`;
- its diff from that parent changes only this preregistration, the machine plan,
  and the matching review packet;
- both external reviews bind the same exact commit and return P0=0 and P1=0;
- the tag did not exist before the review gate and is created as a lightweight
  ref pointing directly to that commit; annotated tags are forbidden;
- the tag is created once and may never be force-updated; both
  `git rev-parse refs/tags/current-source-e4-conformance-20260831-v1` and
  `git rev-parse refs/tags/current-source-e4-conformance-20260831-v1^{commit}`
  must equal that same candidate commit immediately before dispatch and again
  after provider completion;
- the workflow and four fixed witness/specification sources have the SHA-256
  values recorded in the machine plan; and
- no workflow, code, seed, fixture, threshold, expected output, or claim rule is
  changed after review.

## 4. Fixed execution

The only scientific workflow is
`.github/workflows/strong-whole-query-witness.yml`, dispatched on GitHub-hosted
`ubuntu-latest` at the immutable tag.  It has a frozen 120-minute job timeout,
`BUILD_JOBS=2`, `OMP_NUM_THREADS=2`, CPython 3.12, and OpenFHE 1.5.1 at exact
commit `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`.  The controller command is:

```text
gh workflow run strong-whole-query-witness.yml \
  --ref current-source-e4-conformance-20260831-v1
```

The Mac does not run the OpenFHE build or witness.  Queue time is descriptive
provider metadata and cannot become a performance result.

## 5. Fixed deterministic corpus

The property-contract seed remains `20260822`.  The exact eight cases and 35
records are:

| Case | Records | Frozen contract family |
|---|---:|---|
| `base-only-global-ci` | 3 | direct oracle, OutputPlan/F1-M, global-column no-modulo |
| `mixed-multiwave-tombstone` | 12 | oracle/binding retarget rejection, multiwave tombstones, hidden ownership, durable ledger |
| `c128-boundary-127` | 4 | oracle, OutputPlan/F1-M, global column, `c=128` boundary |
| `c128-boundary-128` | 4 | same frozen boundary family |
| `c128-boundary-129` | 4 | same frozen boundary family |
| `c128-multipage-257` | 4 | oracle, OutputPlan/F1-M, global column, multipage segmentation |
| `persistent-strong-transition` | 1 | persistent strong state transition |
| `seeded-extension` | 3 | oracle, OutputPlan/F1-M, deterministic extension |

The one real encrypted fixture is fixed at 4096 rows, 8193 columns, global
column 8192, segment width 128, active delta payload 127, padding offset 127,
and three returned ciphertexts.  The prespecified centered sparse result is
`[(0, 128), (4095, 5)]`.

## 6. Attempt and optional-stopping rule

The default and intended count is one provider run.  No GitHub rerun button may
be used.  Exactly one provider-only replacement is permitted only if every one
of these facts is independently visible:

1. the first run is terminal non-success;
2. checkout never completed successfully;
3. the property-contract step never started;
4. a complete, all-pages `filter=all` GitHub jobs-API receipt shows that no
   returned step ever entered `in_progress` or `completed`, every returned
   step has null `started_at` and `completed_at`, and provider `total_count`
   equals the number of collected jobs;
5. the artifact API reports exactly zero artifacts; and
6. the replacement uses the identical tag, workflow, plan, code, and claim
   rules.

Such a run is retained as a provider-only null attempt.  Once checkout succeeds
or any scientific step starts, every non-success is the terminal scientific
NO-GO for this study; no repair, threshold change, or replacement is allowed.

Replacement eligibility is proved directly by that provider jobs-API receipt,
not inferred from artifact count or the workflow finalizer.  Missing, partial,
inconsistent, or unavailable jobs/steps data fails closed and forbids a
replacement.  Consequently, the replacement is limited to a provider failure
before any job step executes.

## 7. Exact pass and NO-GO criteria

PASS requires all workflow steps and the job/run to conclude success on attempt
1, exactly one success-named artifact, the exact 19-file archive, strict
`SHA256SUMS`, source/provenance rehashing against a fresh detached checkout, and
all machine-plan assertions.  In particular:

- `RUN_STATUS.json` is `pass` with `evidence_valid=true` and all four stage
  outcomes `success`;
- property evidence is `pass`, has eight input cases, 35 records, zero failures,
  and seed `20260822`;
- the witness is the fixed CSSC-base-plus-strong-delta fixture and reports valid
  decryptions;
- its centered sparse decryption is exactly `[(0, 128), (4095, 5)]`; and
- it matches both the typed Python plaintext oracle and direct SpMV oracle.

The machine plan names each JSON artifact and records its expected values as
RFC 6901 JSON Pointers.  This includes `RUN_STATUS.json`, whose fixed values are
literal pointer expectations and whose dynamic `/github_run_id` and
`/source_git_sha` fields have explicit pointer-bound comparison rules.
Validators must apply those pointers literally to the named artifact;
flattened-key or semantic reinterpretation is forbidden.

Any mismatch, missing/extra file, checksum failure, source drift, timeout,
provider failure after checkout, validator failure, or incomplete criterion is
NO-GO.  A NO-GO records the exact prefix but releases no correctness sentence.

## 8. Independent artifact audit

After provider completion, a clean controller process must record the exact run
identity and every step conclusion; query the artifact API; download the raw ZIP
without using it as code; verify its raw SHA-256 against the provider digest;
extract it into a fresh temporary directory; require the exact 19-file set;
verify `SHA256SUMS --check --strict`; parse all canonical JSON; and rehash every
source listed by `PROVENANCE.json` against a fresh detached checkout of the tag.
The controller then produces a separate audit note.  It may not alter the
artifact, rerun a validator to manufacture missing evidence, or infer success
from logs alone.

## 9. Claim release boundary

If and only if every criterion passes, the manuscript may add one bounded
sentence of this form:

> At exact source `<sha>`, the prespecified OpenFHE 1.5.1 whole-query witness for
> one fixed 4096-by-8193 CSSC-base-plus-strong-delta fixture decrypted to the
> prespecified sparse vector and matched both independent plaintext oracles;
> all 35 records in the eight-case deterministic contract corpus passed.

The sentence must name the exact source, run, and artifact digest.  It cannot be
generalized to candidate admission, mixed-circuit safety, security, deployment,
performance, speedup, ranking, or universal correctness.  If the study is
NO-GO, only its factual terminal disposition may be reported.

## 10. Pre-dispatch review gate

The same byte-identical review packet is sent to ChatGPT Pro at the strongest
available reasoning setting and ZCode GLM-5.3 Max.  Dispatch is forbidden until
both bind the exact candidate and report P0=0 and P1=0 on scientific
independence, attempt policy, identity binding, acceptance criteria, and claim
scope.  Fable 5 is consulted only if those two reviews disagree or leave a
P0/P1 unresolved.  External models are advisory; repository facts and provider
records remain authoritative.

# Current-source E4 conformance external gate — 2026-08-31

## Exact reviewed object

- Candidate commit: `844fb062d78f5095f14599c6c71a27cb6034f001`
- Tree: `74a5d7947699dfe2d4910a26ef0d4921a0573220`
- Sole parent: `187347f80ad4333749528229891bd65b8f3a518b`
- Parent-relative binary diff SHA-256:
  `4bbb84005fcef91b9dbba1c1a9be864fed0cfc0de14ff1cedb6e20f6206a04d2`
- Machine plan SHA-256:
  `2c61aca5a45899e278ce2771edd171e37e925f2ac7d8c886a147b2d44e40e2d5`
- Preregistration SHA-256:
  `7966710b677a4eefc9366538d43ea3f7cadec5ed87618be17421745e076c0f85`
- Review packet SHA-256:
  `a8498eceab0b2a8f9ae14dbc473d1645a9269b0b2fa62773b12b23be1c0b9eaf`

The candidate changes exactly those three preregistration/review paths. It
changes no workflow, implementation, dependency, seed, fixture, expected
vector, threshold, or claim rule. The candidate source tag was absent and the
workflow-path provider inventory contained exactly the two disclosed
historical runs throughout both reviews.

## Exact-head CI

Run `33375296854` (`push`, attempt 1) completed `success` at exact head
`844fb062d78f5095f14599c6c71a27cb6034f001`. Every visible step succeeded.
Pytest reported `2667 passed, 2 skipped`; both skips were the expected
`tests/test_publication_day1b_openfhe_execution.py:177` skip because the real
OpenFHE query runner was not built in the generic CI job.

The sole R0 artifact is ID `9752473489`, name
`r0-freeze-844fb062d78f5095f14599c6c71a27cb6034f001`, size `6,837,917` bytes,
provider digest
`sha256:41603661336a835b8fb59a14761cd89a7691d066afc48c372d761369cc9bb344`,
with exact run/head binding and 30-day retention.

## ChatGPT Pro independent review

- Channel: signed-in ChatGPT Pro through Ego Lite, in the existing paper
  Project.
- Setting: Pro, Extra High.
- Exact prompt object: the candidate and hashes above, terminal-success CI as
  a prerequisite, and a read-only adversarial gate.
- Verdict: **PASS — P0=0, P1=0, P2=0**.

Pro independently recomputed the three file hashes, the binary diff, all five
frozen scientific-file hashes, the raw R0 ZIP digest, the two historical
19-file artifacts, and the historical query/output transition. It applied the
new RFC 6901 pointers to the actual artifact schemas and used prior run
`33348855548` to test the provider-only replacement boundary. It found no
remaining blocker.

## ZCode independent review

- Channel: local ZCode app, project `dynamic-cssc-spmv-followup-stage2`, task
  `Adversarial preregistration review of E4 conformance packet`.
- Setting: GLM-5.3, Max, Full access.
- Exact prompt object: the same candidate and hashes above, terminal-success
  CI as a prerequisite, and a read-only adversarial gate.
- Verdict: **PASS — P0=0, P1=0, P2=3**.

ZCode independently verified the candidate commit/tree/parent/diff, document
hashes, exact-head CI, R0 artifact, frozen scientific-file hashes, source-tag
absence, complete workflow-path run inventory, both historical provider ZIPs,
the 19-file layout, actual JSON pointer paths, and live jobs-API semantics. It
confirmed that the superseded review blockers are closed and found no hidden
second result-bearing path.

### Recorded ZCode P2 findings

These findings do not alter the outcome, authority, frozen scientific object,
or permitted claim. They are retained here rather than changing the already
reviewed candidate.

1. The enumerated earlier-to-later query transition does not mention the
   historical fixture's `matrix_value_bound` change from 16 to 7. The three
   query-value changes and both historical sparse outputs were independently
   byte-verified; the current object is hash-frozen from the later anchor.
2. The preregistered independent-audit list does not explicitly require the
   complete workflow-path inventory to equal the two historical runs plus at
   most the preregistered current attempts. The controller will perform and
   record this stricter inventory check before dispatch and again during the
   terminal audit; an unexpected run is a protocol breach and cannot support a
   positive claim.
3. The provider-only replacement rule does not specify transient jobs-API
   outage retry timing. If a provider-only null attempt ever occurs, the
   controller will capture the persistent post-terminal provider record after
   service recovery; a permanently unobtainable, partial, or inconsistent
   receipt forbids replacement. This does not authorize a rerun button or a
   second result-bearing attempt.

## Shared ZCode quota observation

The BigModel Coding Plan quota is shared by all ZCode instances. At 17:05
Asia/Shanghai, the five-hour pool was 100% used with reset at 18:31, the weekly
pool was 94% used with reset at 2026-09-02 10:00, and MCP monthly usage was 9%.
After the five-hour reset, the usage page showed 0% for that pool while weekly
usage remained 94%. Therefore only this one gate-critical ZCode review was run;
no duplicate status prompts or lower-priority ZCode tasks were issued.

## Gate disposition

**PASS — both independent reviewers bind the exact candidate with P0=0 and
P1=0.** The external-review condition for create-once tag installation is
satisfied. This record does not itself report an experimental result. The tag
must remain a lightweight direct ref to the exact candidate, the workflow may
be dispatched at most once by default, and any terminal result must undergo
the complete independent raw-artifact audit before any manuscript claim is
released.

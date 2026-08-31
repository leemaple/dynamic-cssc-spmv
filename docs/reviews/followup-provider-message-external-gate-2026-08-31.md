# Follow-up provider-message repair external gate — 2026-08-31

## Gate object and boundary

- Candidate commit:
  `fc65fd4e77e0133ee0e1338471c4fbad0bff2f8d`
- Tree: `3ea4d985e5fe17e74f94411d9c8203df6f79f753`
- Sole parent: `8d3bcad050ea0945133c2096ac0667d0de57af96`
- Parent-to-candidate binary-diff SHA-256:
  `8c3909010067e4013687426c1021f381da21a32fc9e85be4b965e0614ccb5093`
- Review packet: 138 lines, 7,110 bytes, SHA-256
  `d904b637b3387034a24f2f1e54dea0dc0543452eba167dbd41b6bcb1a9ddcb85`
- Authority boundary: read-only material/design review. Neither reviewer could
  authorize a study, reopen either terminal NO-GO, weaken the one-shot rule,
  or treat the authority-false provider drill as scientific evidence.

The same packet was submitted once to both reviewers. The packet froze the
exact candidate, the authority-false drill receipt, the observed 422-byte
request versus 421-byte provider response, the six requested review axes, and
the requirement to return `PASS`, `AMEND`, or `FAIL` with P0/P1/P2 findings.

## ChatGPT Pro review

- Channel: signed-in ChatGPT Pro through Ego Lite, paper Project
  `矩阵向量乘法论文`
- Mode visible at dispatch and completion: `Extra High`
- Conversation:
  <https://chatgpt.com/g/g-p-6a843076849c8191ae260f5d4fb84e80-ju-zhen-xiang-liang-cheng-fa-lun-wen/c/6a951a27-fcac-83ec-a9c2-7a29c985288f>
- Packet identity: independently verified as 7,110 bytes, 138 lines, and the
  exact SHA-256 above
- Verdict: **PASS — P0=0, P1=0**

Pro independently verified the public commit/tree/parent, branch target,
21-path diff, remote diagnostic tag, authority-false same-tree drill commit,
historical terminal run state, and zero-artifact boundary. It found the
one-line-feed translation fail-closed, all producer and consumer surfaces
covered, the five Behavior Set advances appropriate, and the historical
diagnosis correctly limited to a high-confidence same-code-path reproduction.

Pro recorded three nonblocking P2 items:

1. the packet said seven producer call sites although the exact source has one
   generic wrapper plus seven direct qualification/terminal/analysis calls;
2. the cause-chain redactor is sufficient for the demonstrated provider path
   but is not a general secret sanitizer, and a future implementation should
   respect `__suppress_context__`; and
3. the already disclosed expected-404 limitation in the CLI transport is real
   but is outside every reviewed production success-status path.

## ZCode review

- Channel: local ZCode application, project
  `dynamic-cssc-spmv-followup-stage2`
- Model/mode visible throughout: `GLM-5.3`, `Max`, `Full access`
- Task: `Verify SHA-256 of followup-provider-message file`
- Packet identity: independently verified byte-exact before review
- Verdict: **PASS — P0=0, P1=0, P2=3 (none blocking)**

ZCode independently reproduced the remote byte accounting: the live stored
message is 421 bytes without a final line feed and its digest matches the
drill receipt; restoring one line feed reproduces the 422-byte request and its
recorded digest. It verified all eight producer invocations, all four admission
readers, both controller authority-validation branches, the five Behavior Set
advances, the all-false drill flags, and the frozen scientific boundary.

ZCode created and then removed a detached scratch worktree at the exact commit.
After distinguishing failures caused by a history-less extraction from code
failures, it ran a focused superset with **139 passed, 0 failed**. It did not
edit the candidate, push, dispatch, expose a seed, or touch the submitter's
control-plane worktree.

Its three nonblocking P2 items were:

1. correct the packet's seven/eight call-site wording in the verdict record;
2. record that the diagnostic formal-watch observation embeds the provider's
   line-feed-free representation, so any future consumer must use the shared
   boundary before canonical inspection; and
3. treat the current credential redaction as targeted defense in depth rather
   than a complete sanitizer for arbitrary values such as raw JWTs.

## Exact-head CI closure

GitHub Actions run
[`33362392307`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33362392307)
completed successfully on the exact candidate after Pro's final snapshot and
before ZCode's final verdict.

- P-1 manifest gate: success
- Python syntax check: success
- Full suite: `2667 passed, 2 skipped in 1261.99s`
- The two skips were only
  `tests/test_publication_day1b_openfhe_execution.py:177` because the hosted CI
  job does not build the real OpenFHE query runner
- Predicted-only smoke: success
- R0 bundle creation/upload: success
- Artifact ID: `9747549300`
- Artifact name:
  `r0-freeze-fc65fd4e77e0133ee0e1338471c4fbad0bff2f8d`
- Artifact size: 6,802,213 bytes
- Artifact digest:
  `sha256:39bdaa938190b0ab655e7bf2dc036a1abd62ac4e2ca9c743929dbfc78582049d`

The artifact was not downloaded or installed. Its API metadata binds it to run
`33362392307`, branch `codex/future-study-control-plane-drill`, and exact head
`fc65fd4e77e0133ee0e1338471c4fbad0bff2f8d`.

## Finding disposition

- **Accepted and corrected in this record:** the exact source contains eight
  syntactic `_create_message_commit` invocations apart from its definition.
  All eight are repaired. The frozen input packet is retained unchanged as the
  reviewed object.
- **Accepted and recorded for future consumers:** a provider message embedded
  in a diagnostic observation remains provider representation. Any future
  canonical consumer must pass it through
  `canonical_json_from_github_commit_message`.
- **Deferred, nonblocking hardening:** broaden diagnostic secret sanitization,
  respect `__suppress_context__`, and harden explicitly expected non-2xx CLI
  transport handling in a separately reviewed change. None is reachable as an
  authority bypass in the reviewed production paths.
- **Rejected as unsupported:** no reviewer found a basis to reopen either
  stopped study, refund a one-shot qualification, authorize formal execution,
  or claim a performance result from the drill.

## Final disposition

**PASS — P0=0, P1=0.** The exact candidate and exact-head CI are admissible for
merge as a prospective, fail-closed control-plane repair. Fable 5 was not
invoked because repository evidence, ChatGPT Pro, and ZCode converged without a
P0/P1 disagreement or unresolved material uncertainty.

This gate does not change the publication status: both earlier studies remain
terminal NO-GO and admitted formal experimental results remain zero. Any new
execution must belong to a separately preregistered, scientifically independent
study with new lineage and full disclosure of both NO-GOs.

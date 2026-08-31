# Follow-up provider message/CAS diagnosis — 2026-08-31

## Scope and authority boundary

This is an authority-false, post-outcome engineering diagnosis. It does not
reopen the terminal follow-up study, authorize a second qualification, expose a
registered seed, dispatch a workflow, or create publication evidence. The
dedicated diagnostic ref is outside every qualification, formal, terminal, and
analysis namespace.

## Exact remote drill

- Repository: `leemaple/dynamic-cssc-spmv`
- Base commit: `8d3bcad050ea0945133c2096ac0667d0de57af96`
- Base/candidate tree: `f367ee43c380d52155d423b1f187f22a7084f210`
- Dedicated ref:
  `refs/tags/dynamic-cssc-provider-cas-drill-authority-false-20260831-v1`
- Installed authority-false candidate:
  `422fda82867d4159c46e1328206b588aedc21f6b`
- Receipt:
  `docs/reviews/followup-provider-cas-drill-receipt-2026-08-31.json`
- Receipt SHA-256:
  `8f6c56bd36ee19e12b31772c979a1115aea88a17794f2a14e26c265d8756bcf8`

The candidate is a direct child of the base and has the same tree. Its message
states `authority_granted=false`, `experiment_dispatch_authorized=false`, and
`formal_execution_authorized=false`. No Actions workflow was dispatched and no
seed, result, or artifact was created.

## Observed failure and discriminating result

The first live production-adapter probe created the dedicated ref at the base,
then stopped before CAS with:

```text
FollowupCampaignControlError: created campaign state commit changed
```

A resumed probe recorded the exact REST response instead of discarding it. The
request contained a 422-byte canonical JSON message ending in one line feed;
GitHub returned the same JSON in 421 bytes with exactly that final line feed
removed. Every other checked identity matched: candidate SHA, one parent, and
tree. The official GitHub create-commit response contract includes the
`message`, `parents`, `tree`, and `sha` fields:
<https://docs.github.com/en/rest/git/commits#create-a-commit>.

The same candidate then passed the repository's production GraphQL
`updateRefs` compare-and-swap implementation. A fresh provider read showed the
dedicated ref at the exact candidate. This falsifies a persistent permission or
GraphQL-CAS incompatibility on the authenticated repository path used by the
controller.

## Root cause and historical inference

The production adapter sent internal canonical JSON, including its required
final line feed, as a GitHub commit message and then required the REST response
message to be byte-identical. GitHub's response projection omits that final
line feed, so `_create_message_commit` rejected a commit GitHub had already
created. The run-admission scripts had the mirror defect: they passed GitHub's
line-feed-free response directly to inspectors that require canonical JSON with
one final line feed.

This defect deterministically affects the qualification watcher-binding path
that the terminal run `33348855548` traversed, and its outer error is exactly
the recorded `qualification watcher could not be armed before seed admission`.
Because that historical process did not persist its nested exception, the
diagnosis is a high-confidence same-code-path reproduction, not a claim that
the missing historical exception was recovered.

## Repair contract

The repair keeps internal receipts unchanged and introduces one narrow GitHub
boundary:

1. internal documents must remain duplicate-free canonical ASCII JSON ending
   in exactly one line feed;
2. only that final line feed is removed before creating a GitHub commit;
3. the GitHub response must match the resulting provider representation
   exactly; and
4. provider messages regain exactly one final line feed before existing
   receipt inspectors run.

Whitespace changes, duplicate keys, non-finite values, non-ASCII bytes, missing
or extra final line feeds, topology changes, and CAS mismatches still fail
closed. The CLI additionally preserves a bounded, redacted nested exception
chain so a future pre-seed failure is diagnosable without exposing credentials.

Production-faithful red tests initially produced 12 failures spanning
qualification, formal campaign, terminal, and analysis admission. After the
single boundary repair, the focused suite completed with 101 passing tests.

## Frozen disposition

This diagnosis cannot refund the consumed one-shot follow-up qualification.
The existing follow-up remains terminal NO-GO and formal execution for that
study remains forbidden. The repair is prospective infrastructure for a
scientifically independent future study whose estimand, preregistration,
lineage, and disclosure obligations must be reviewed separately.

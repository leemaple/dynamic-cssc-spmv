---
name: external-expert-escalation
description: Coordinate material paper and protocol review through ChatGPT Pro and ZCode, including the preferred ChatGPT Pro browser channel, and escalate to Fable 5 only when repository evidence plus those reviews still do not converge. Do not use external review as a substitute for tests and experiments.
---

# External Expert Review and Escalation

External reviewers challenge a bounded question. Their output is a hypothesis
source, not authority.

## Reviewer channels

For a browser-based ChatGPT Pro exchange, use the already signed-in Ego Lite
session through the project-available `ego-browser` capability first. Reuse the
existing paper Project and its relevant historical conversation when their
identity and scope match the current gate. Verify the visible Project/thread and
the exact review packet before sending; the login state or conversation history
does not establish repository facts.

Use another already authorized browser channel only when Ego Lite is unavailable
or its session is broken, and record that fallback in the review note. Submit a
bounded packet once and allow Pro's long reasoning response to finish; resend only
after a clear transport or session failure.

Use ZCode at its strongest currently configured reasoning mode when available.
Quota loss is an availability fact, not a reason to weaken a gate. Record the
reviewer, model/mode when visible, channel, exact packet identity, and final
verdict alongside the local evidence.

Use Fable 5 only as the escalation reviewer described below.

## Trigger

Escalate only when the decision can materially affect the paper's validity,
experimental cost, protocol claims, or schedule, and at least one condition is
true:

- repository evidence and the available ChatGPT Pro/ZCode reviews leave a P0 or
  P1 disagreement;
- the reviewers converge on uncertainty rather than a testable resolution; or
- diagnosis has stalled between competing hypotheses after a reproducible local
  probe.

Continue ordinary work without escalation when source, tests, or workflow logs
already decide the question. Reviewer quota loss alone is not an escalation
trigger.

## Review packet

Establish the facts before contacting the reviewer. Send a compact packet that
contains:

- exact repository SHA, branch, bounded diff, and relevant run/artifact IDs;
- the single decision or claim being gated;
- direct observations separated from inferences;
- competing hypotheses and the evidence for and against each;
- frozen preregistration, threat-model, and claim boundaries that the answer may
  not silently rewrite; and
- the cheapest discriminating test or measurement already attempted.

Ask for `PASS`, `AMEND`, or `FAIL`, P0/P1/P2 findings, explicit assumptions, and
the minimum falsifying checks. Ask the reviewer to distinguish defects in the
system from defects in the evidence pipeline.

## AIGoCode handling

Use only an already authorized AIGoCode session or credential. Discover the live
model catalog and select the exact Fable 5 model only when it is currently
listed; never guess a model alias, bypass a provider restriction, expose a token,
or persist a credential in the repository. Prefer a streaming response when the
provider times out on long non-streaming requests. When Fable 5 is actively
reasoning, let that response finish instead of resending the packet or polling
aggressively.

If Fable 5 or the authorized channel is unavailable, record that fact and
continue with local verification. Availability must not block safe progress.

## Cross-examination

Map every material recommendation to repository source, a frozen artifact, a
test, or a proposed discriminating experiment. Return concrete counterevidence
for factual conflicts and require the reviewer to retain, revise, or withdraw
each disputed finding.

Use at most one initial review and one counterevidence round for the same packet.
Further model discussion requires new evidence or a materially changed question.

## Disposition

Record accepted, rejected, and deferred findings with their evidence. A finding
may change implementation or the next diagnostic probe only after local
verification. It cannot by itself authorize an experiment, weaken a frozen gate,
change a preregistered estimand, expand the threat model, or support a paper
claim.

The escalation is complete when each P0/P1 is either closed by evidence, turned
into a named discriminating test, or explicitly left as a blocker. Then return
to implementation or measurement; do not treat reviewer agreement as completion.

For a worked example of the required challenge-and-disposition pattern, consult
`docs/reviews/fable5-stop-loss-audit-2026-08-27.md`.

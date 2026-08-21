# ADR 0006: Advance independent persistent strategy snapshots

- Status: Accepted
- Date: 2026-08-22

Day 1 advances one independent persistent snapshot per maintenance strategy through every
ordered Publication Window. Warmup and tuning windows change state even when their costs
are excluded from held-out metrics. Each transition validates the complete candidate
matrix version, publishes version-matched CSSC components, and requires decoding those
components to reproduce the logical state before it commits.

This replaces the static initial-layout `WindowShape` proxy. A general event-sourced replay
framework was rejected because it adds checkpoint, cache, and projector machinery that the
experiment does not need. The minimal causal selector is a tuning-only `TunedFixedPolicy`:
its configuration is frozen before held-out evaluation and continues from its own
post-tuning snapshot. `BestFixed-Offline-Oracle` remains a diagnostic bound and is never a
selector input. Online cross-strategy switching remains out of scope until migration or
parallel-maintenance costs are modeled.

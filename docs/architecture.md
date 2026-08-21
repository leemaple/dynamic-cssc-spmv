# Architecture

## Research pipeline

```text
P-1 manifest
    ↓
P0a actual BFV layout probe
    ↓
Day 1 exact layout/count simulator
    ↓ required rotation indices
P0b key plan + Day 2 measured unit costs
    ↓
held-out Pareto gate
    ↓
minimal OpenFHE prototype
```

## Functional modes

- **F1-M Hidden-RowMap** is the default publication mode.
- **F1-L** is allowed only as an explicitly weaker leakage experiment.
- **F2** is an extension requiring cloud-side physical output alignment.

## Strategy classes

Reference strategies: Static-CSSC, PaddingReuse, ReservedSlack, Mini-CSSC-Delta, Packed-COO/HYB, Strict LocalRepack, and PeriodicRepack.

Candidate contributions: causal hybrid selector, new overflow layout, cloud/client merge selection, version/freshness protocol, and complete Hidden-RowMap F1-M accounting.

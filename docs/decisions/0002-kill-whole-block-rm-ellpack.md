# ADR 0002: Kill whole-block RM-aligned ELLPACK delta

- Status: Accepted
- Date: 2026-08-21

The layout is killed because its ciphertext group count is governed by the busiest row, causing catastrophic padding under skewed updates. It remains only as a negative control.

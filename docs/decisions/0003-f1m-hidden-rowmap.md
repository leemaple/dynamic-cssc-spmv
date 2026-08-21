# ADR 0003: F1-M Hidden-RowMap as default

- Status: Accepted
- Date: 2026-08-21

The default endpoint is client decryption. Split base/delta outputs must not reveal their individual logical products. Client A therefore supplies one-time encrypted zero-sum masks mapped into each component's physical output layout. Server-only plaintext masking is allowed only in a separately labeled Public-RowMap leakage mode.

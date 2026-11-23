# Caatinga friction log

Honest notes from building this project with `@caatinga/cli` 3.14.0 and Stellar CLI 28.0.0.

| Date | Step | Friction | Workaround |
| --- | --- | --- | --- |
| 2026-11-23 | `ctg zk init` template in a Cargo workspace | The verifier crate carries its own `[profile.release]` and `crate-type = ["cdylib"]`; inside a workspace the profile is ignored and other crates cannot depend on it for tests | Moved the profile to the workspace root, added `rlib` |
| 2026-11-23 | `ctg doctor` on a fresh repo | Reports `blocked` until `caatinga.artifacts.json` exists, even before any deploy | Created an empty v2 artifacts file |
| 2026-11-23 | `ctg doctor` | Warns `STELLAR_SDK_UNTESTED_VERSION` for @stellar/stellar-sdk 17.4.0 pulled transitively | None needed yet |
| 2026-11-23 | Funding the identity | `stellar keys generate --fund` only prints "Unable to fund account" when friendbot is unreachable (corporate proxy), no reason | Fund from a network that reaches friendbot |
| 2026-11-23 | Multi-contract config | `${source.address}` and `${contracts.x.contractId}` placeholders made the 4-contract graph wiring painless | — |
| 2026-11-23 | `ctg zk build` with circomlib | circom is invoked without `-l`, so `include "circomlib/..."` does not resolve | Relative includes into `../../node_modules/circomlib/` |
| 2026-11-23 | Off-chain witness inputs | No helper to compute Poseidon in the BLS12-381 field off-chain (circomlibjs is BN254 only) | Compiled a small hasher circuit and used its witness calculator |
| 2026-11-23 | circom wasm witness in an ESM repo | `generate_witness.js` is CommonJS and breaks under `"type": "module"` | Wrote `{"type":"commonjs"}` into the generated `main_js/` |
| 2026-11-23 | VPS build (disposable container) | No ready image with Rust 1.91.1 + Stellar CLI 28 + Node 22 | Toolchain assembled by hand; build and 21/21 tests OK, no other friction |

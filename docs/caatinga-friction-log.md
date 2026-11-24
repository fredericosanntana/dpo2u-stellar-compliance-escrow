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
| 2026-11-23 | `ctg doctor` in a Cargo workspace | Reports "soroban-sdk not found" for all 4 contracts because it does not follow `soroban-sdk = { workspace = true }` (false negative) | Ignored; the build works |
| 2026-11-23 | `ctg status` | Repeats the "add a frontend section" hint for every contract (24 lines), no way to silence it | None |
| 2026-11-23 | `ctg deploy` | Rewrites `caatinga.artifacts.json` and moves `"version": 2` to the end, a noisy diff | None |
| 2026-11-23 | VPS testnet deploy | No ready image with Rust 1.91.1 + wasm32v1-none + Stellar CLI 28 + Node 22 | Toolchain assembled by hand in a disposable container |
| 2026-11-24 | `ctg deploy` after a wasm change | Plain deploy skips every contract as "already deployed" even when the wasm changed, with no warning, and still rewrites the artifacts file | `--force` / `--if-changed` |
| 2026-11-24 | `ctg deploy --force` | Adds `history` and `upgradeStrategy` to the artifacts file; neither is documented in `--help` | None |
| 2026-11-24 | circom download in CI/VPS logs | The progress bar prints hundreds of lines without a TTY | None |
| 2026-11-24 | Calling gate/escrow with a snarkjs proof | No helper converts snarkjs JSON to Stellar CLI arguments (G1 96 bytes, G2 192 bytes big-endian, G2 as c1‖c0); `ctg zk invoke` only covers the verifier | Wrote a converter, checked with a simulated `verify_proof` |
| 2026-11-24 | `ctg zk build` on another machine | Always regenerates the dev setup; without the original zkey the VK cannot be reused, so a new context forces a policy rotation | Rotated policy 1 (same policy_hash and window) |
| 2026-11-24 | `ctg build` for the Midnight verifier | Produced a 46 KB wasm instead of the 91 KB `cargo build --release` output (the size-optimized build costs ~361M CPU for the TravelRuleGate proof vs 313M) | Deployed the cargo wasm; `npm run build` now calls cargo directly |
| 2026-11-24 | Getting testnet USDC for the DvP buyer with a Stellar CLI path payment | The CLI needs the exact issuer of the intermediate asset in the path (USTRY), with no lookup | Looked the issuer up on Horizon and passed it explicitly |

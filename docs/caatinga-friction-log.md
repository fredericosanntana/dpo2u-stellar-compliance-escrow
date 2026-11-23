# Caatinga friction log

Honest notes from building this project with `@caatinga/cli` 3.14.0 and Stellar CLI 28.0.0.

| Date | Step | Friction | Workaround |
| --- | --- | --- | --- |
| 2026-11-23 | `ctg zk init` template in a Cargo workspace | The verifier crate carries its own `[profile.release]` and `crate-type = ["cdylib"]`; inside a workspace the profile is ignored and other crates cannot depend on it for tests | Moved the profile to the workspace root, added `rlib` |
| 2026-11-23 | `ctg doctor` on a fresh repo | Reports `blocked` until `caatinga.artifacts.json` exists, even before any deploy | Created an empty v2 artifacts file |
| 2026-11-23 | `ctg doctor` | Warns `STELLAR_SDK_UNTESTED_VERSION` for @stellar/stellar-sdk 17.4.0 pulled transitively | None needed yet |
| 2026-11-23 | Funding the identity | `stellar keys generate --fund` only prints "Unable to fund account" when friendbot is unreachable (corporate proxy), no reason | Fund from a network that reaches friendbot |
| 2026-11-23 | Multi-contract config | `${source.address}` and `${contracts.x.contractId}` placeholders made the 4-contract graph wiring painless | — |

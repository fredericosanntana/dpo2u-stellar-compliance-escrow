# DPO2U Stellar Compliance Escrow

**Compliance as a protocol on Stellar.** A Soroban escrow that releases a payment (testnet USDC) or a tokenized security only when a zero-knowledge proof shows the transfer satisfies data protection (LGPD/GDPR), the Travel Rule, sanctions screening and PSAV/CVM rules, without putting personal data on-chain.

> Midnight keeps the secret, Stellar moves the money, and the proof is the same.

Status: **phase 4 done on testnet**: a real Midnight TravelRuleGate proof released testnet USDC on Stellar (phase 3) and settled a delivery-versus-payment trade of a test security against testnet USDC (phase 4). Testnet only. No real funds.

## Contracts

| Contract | What it does | State |
| --- | --- | --- |
| `compliance-escrow` | Locks a Stellar asset (SAC), releases it with an accepted proof bound to that escrow (`release` for Circom, `release_midnight` for Midnight), refunds after the deadline | working, on testnet |
| `compliance-dvp` | Delivery versus payment: a security token and USDC change hands in one call, only with an accepted proof bound to that trade; the token issuer's holder authorization still applies | working, tested (`docs/cvm-package.md`) |
| `compliance-gate` | Pins the policy per `policy_id` (sanctions root, pepper commitment, policy hash, freshness window, verifier key) and checks proofs against it and a Midnight lane (pinned statement values, escrow context as the TravelRuleGate `transfer_id`) | working, on testnet (both lanes) |
| `circom-verifier` | Groth16 / BLS12-381 verifier from Caatinga's `zk-starter` | working, on testnet (sanctions non-membership circuit) |
| `midnight-verifier` | Verifies Midnight's own proofs (Plonk + KZG over BLS12-381) inside Soroban | verifies real Midnight ledger proofs in wasm: 313M CPU for the TravelRuleGate v12 proof (`docs/midnight-verifier.md`); on testnet |

```
payer --deposit--> compliance-escrow --check_circom--> compliance-gate --verify_proof--> circom-verifier
                         |                                     \--(phase 3)--> midnight-verifier
                         \--SAC transfer--> beneficiary (PASS) / payer (refund)
```

A proof is accepted only if its public signals match what the gate pinned **and** the escrow's `context` (a hash of escrow contract, id, beneficiary, asset, amount, deadline and policy), so it cannot be replayed on another escrow. Signal layout: [docs/circuit.md](docs/circuit.md).

## Quick start

Requires Rust 1.91.1 with `wasm32v1-none`, Stellar CLI ≥ 23 (tested with 28.0.0) and Node 22.

```bash
npm install
cargo test --workspace              # 21 tests
npx ctg build                       # builds the 4 wasm files
stellar keys generate dpo2u-escrow-testnet --network testnet --fund
npx ctg doctor --network testnet --source dpo2u-escrow-testnet
npx ctg deploy --network testnet --source dpo2u-escrow-testnet -y   # full graph, in dependency order
npx ctg status --network testnet
```

Contract IDs are written to `caatinga.artifacts.json` and wired through `${contracts.<name>.contractId}` in [`caatinga.config.ts`](caatinga.config.ts); nothing is copied by hand.

## Documents

- [Compliance and risk](docs/compliance-and-risk.md): LGPD + Travel Rule + sanctions + PSAV/CVM, and how each becomes a protocol rule
- [Threat model](docs/threat-model.md)
- [Circuit and public signals](docs/circuit.md)
- [Cost analysis](docs/cost-analysis.md)
- [Caatinga friction log](docs/caatinga-friction-log.md)

## Roadmap

0. Scaffold, escrow and gate (done)
1. Sanctions non-membership circuit (indexed Merkle tree, pepper scheme), real Groth16 release of testnet USDC (done, on testnet)
2. `midnight-verifier`: no_std port of the midnight-proofs 0.8.2 verifier, VK exported to an SVK blob (done)
3. Real Midnight TravelRuleGate proof releasing testnet USDC on Stellar (done, on testnet)
4. CVM package: `compliance-dvp` (delivery versus payment of a receivable token against USDC, settled only with a compliance proof; the issuer's holder authorization still applies), [docs/cvm-package.md](docs/cvm-package.md), [demo video script](docs/demo-video-script.md) (done, on testnet)

## License

Apache-2.0

## Testnet deployment (phase 0, commit 7258c7d)

| Contract | ID |
| --- | --- |
| circom_verifier | `CBV7I5JHH4VDF3BAU33N3BJ7RUGQBO725DD5FEJ2HYSVJY6MD2ZIOUBZ` |
| midnight_verifier | `CDV3EF7E2SAHBIVXEL7Y3EI7SCX5HKFOWJOWU4LXCREXEKJYOJTGFARL` |
| compliance_gate | `CDJ4Z2HJ6QWF7E45WBOEHUBCQB35EK2NU7EDV2QBCXKX7DDPU4E4B7JE` |
| compliance_escrow | `CCZC6E2ZRQON7JXP7VBDS5UTXEJX23MTF4E7U55QIDEKE57PEWPX6KKM` |

Admin: testnet-only identity `GB6JK2QZMCM55HQH64KMQE6G4MCZBQHRR66QEY6DI4UOKZMCKAZYRMEY`. `ctg smoke` passes (gate.admin, escrow.gate, midnight_verifier.vk_hash).

## Testnet deployment (phase 1, commit 8ed6335)

Full flow on-chain: `set_policy`, `deposit` of 1 testnet USDC, `release` with a real Groth16 proof (verdict pass=true). A replayed old proof is refused with `RootMismatch` (#4) in simulation.

| Contract | ID |
| --- | --- |
| circom_verifier | `CAO374QVP2NFCXVOXCY7ZTR6FJ4FRP6UXC2O3NFIOKK7SYANWMFSW3FP` |
| midnight_verifier | `CC5KN73DOKIGPEJH3UTLNUSWCTFPP3SZUUSKIRZJRKCWFELNAQHHVQ4U` |
| compliance_gate | `CBH2YR3HNYZBVZBSZNMTUL3XCR6I2WCMZ6GVWQM76MOKX7RT2V7CQID5` |
| compliance_escrow | `CCX6ZTGXA363MKEQR3LVGHPEWDMIADQEWOEZ7VCPFLMMMTXS4E5R473T` |

Release tx: `f1a510fe6c02fd3c46f9ffa0c175f646f34b533a21530e5ba510dc9f01947fb0`. Total fees for the 11 transactions: 0.70 XLM, almost all of it the gate wasm upload; the release itself cost 0.0029 XLM. The testnet policy uses a VK and pepper regenerated on the deploy machine, so it differs from `fixtures/`.

## Testnet deployment (phase 3, commit a9e09a4)

A real Midnight proof released testnet USDC on Stellar. The TravelRuleGate v12 on Midnight **preview** evaluated a transfer whose `transfer_id` is the escrow context. Its `evaluateTransfer` proof, made by the official proof-server, was then verified inside Soroban by `midnight-verifier`. The gate's Midnight lane checked the pins and the context, and the escrow paid.

| Contract | ID |
| --- | --- |
| midnight-verifier | `CDRVMZMAB4HGSEXRST6KQAO7USVLXPON5YIVLSL4ENVJCGQ5L5PBCWBU` |
| compliance-gate | `CDF3F3XCMDIYLGC46JK5IMBQBIM657SEQ6PCUMIOORWVVIQ4OQ2523MG` |
| compliance-escrow | `CBHZIEWBIJC7VYU43NTFZT44IBLAPZT3MYLJZXIGXG3ZQJNIN6UJ7CDU` |

| Step | Tx / value |
| --- | --- |
| `register_vk` (TravelRuleGate v12 SVK, k=17) | `1bcc1c40c3247a59f3fea9b45b578a0861a9f4cda31998162adc3dd71dbe718e`, vk_hash `879336d7478b1b686211d1a055caff8c054434e9b8e61e0b69435b654a810fa5` |
| `deposit` 1 USDC, escrow 1 | `4c46b0369f4befe4f3e2cce1fcdceb86e91864bb94cece7e69344c3fda948f42`, context `00592cfd012267b0b5c5cbada2d5fede666e1966d4cfe6ab6e7462626da3118f` |
| Midnight preview `evaluateTransfer` PASS, `transfer_id` = context | tx `00ba80c550d57bbe044b16b431e3628806ab99574a4a82d22d69a7efe01b783d1b`, block 246649 |
| `set_midnight_policy` (pins: policy hash, list root, pepper commitment, provider, status PASS, no fail reason; context at 202, `Bytes<32>`) | `965aa45285340e9f2484616ea1dcd1c0712efd9b479df891cbf028502d8e317f` |
| `release_midnight` | `ef3e413fae9ddea704600ec217c871a13303cd02d4f69e4bc980439e55debf30`: 328,471,689 CPU instructions (82% of the cap), 0.0162 XLM, events verdict pass=true, transfer 1 USDC, released |

The proof, statement and hints are in `fixtures/midnight/escrow-bound/`. The sanctions snapshot and pepper are fictitious and disposable, and no personal data is involved. Total testnet fees were 9.995 XLM, almost all of it wasm upload. Build the wasm with `cargo build --release --target wasm32v1-none` (`npm run build`): the verifier crates are tuned for speed (`opt-level = 3`), which is what the 313M figure assumes.

## Testnet deployment (phase 4, commit 0af7ec9)

Delivery versus payment of a test security against testnet USDC, settled with a real Midnight proof. The seller offered 10 DPOSEC (a test receivable token whose issuer has `AUTH_REVOCABLE`, so it controls who may hold it) for 250 testnet USDC, and the buyer funded the trade. The TravelRuleGate v12 on Midnight preview then evaluated a transfer whose `transfer_id` is `compliance-dvp.context(1)`. `settle_midnight` verified that proof through the gate's Midnight lane and moved both legs in one call.

| Contract / account | ID |
| --- | --- |
| compliance-dvp | `CBXIFUYO54NEY7PAAQOKWXFA2Z77BAKSDRVWZ7B7S43QGHG4I5XDGWVE` (gate `CDF3F3XCMDIYLGC46JK5IMBQBIM657SEQ6PCUMIOORWVVIQ4OQ2523MG`) |
| DPOSEC issuer (`AUTH_REVOCABLE`) | `GCV5T3PKJPZIIWHMVUQWBNA3LHXPTLZGPWNTDOZRGG5M7YFMRSCVQICN` |
| DPOSEC SAC | `CB6YLZYHWW5CLY4E3YIGRN7HNM3DVG2QKVCFMIGK2LWVFV2ATJYNC5ZX` |

| Step | Tx / value |
| --- | --- |
| `offer` 10 DPOSEC for 250 USDC, trade 1 | `f6265e8df18cad3becbe758e282208c5c1fbc71963af944e082ad804f41ce258` |
| `fund` 250 USDC | `552a81d505c1d813c8ec14a5683fa16b596e7c8cdcba8df72c0fbfc907eae31a` |
| `context(1)` | `00977ba13d51cd64f08cc2c230fe3c7382c86ba74c12d0a73ea436460d82f446` |
| Midnight preview `evaluateTransfer` PASS, `transfer_id` = context | tx `00400f00f7fa897927263e3b6e6357618829343bbb187c8c86fbe6ad55bceb2aec`, block 251180 |
| `set_midnight_policy` 2 (new snapshot: list root and pepper commitment; the rest as policy 1, which stays intact) | `35cb8b72022fb6e6db10940532b1984b357c1bf8ea4841691037d58eba8e4966` |
| `settle_midnight` | `18e0a4157b6b20a1b0cfc6ff7127c9176761f8f9455ef561d4d449058fb368ed`: 328,713,978 CPU instructions (82% of the cap), 0.0166 XLM; 10 DPOSEC to the buyer and 250 USDC to the seller in the same call, trade state `Settled` |

The proof, statement and hints are in `fixtures/midnight/dvp-bound/`. As in phase 3, the sanctions snapshot and pepper are fictitious and disposable, and no personal data is involved.

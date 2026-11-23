# DPO2U Stellar Compliance Escrow

**Compliance as a protocol on Stellar.** A Soroban escrow that releases a payment (testnet USDC) or a tokenized security only when a zero-knowledge proof shows the transfer satisfies data protection (LGPD/GDPR), the Travel Rule, sanctions screening and PSAV/CVM rules, without putting personal data on-chain.

> Midnight keeps the secret, Stellar moves the money, and the proof is the same.

Status: **phase 0** (scaffold). Testnet only. No real funds.

## Contracts

| Contract | What it does | State |
| --- | --- | --- |
| `compliance-escrow` | Locks a Stellar asset (SAC), releases it with an accepted proof bound to that escrow, refunds after the deadline | working, tested |
| `compliance-gate` | Pins the policy per `policy_id` (sanctions root, pepper commitment, policy hash, freshness window, verifier key) and checks proofs against it | working, tested (Circom lane) |
| `circom-verifier` | Groth16 / BLS12-381 verifier from Caatinga's `zk-starter` | template, circuit lands in phase 1 |
| `midnight-verifier` | Verifies Midnight's own proofs (Plonk + KZG over BLS12-381) inside Soroban | interface stub, refuses every proof until phase 2 |

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

0. Scaffold, escrow and gate (this PR)
1. `sanctions_nonmembership.circom` (indexed Merkle tree, pepper scheme), end-to-end BR → MX testnet USDC payment, failure paths
2. `midnight-verifier`: no_std port of the midnight-proofs verifier, generated per circuit
3. Real Midnight TravelRuleGate proof releasing testnet USDC on Stellar
4. CVM package, demo video

## License

Apache-2.0

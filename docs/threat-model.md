# Threat model

## What a release guarantees

- The proof verifies under the verifier key pinned for the policy.
- The beneficiary is not in the sanctions snapshot whose root, pepper commitment and freshness window are pinned in `compliance-gate`.
- The proof is bound to this escrow (`context`): it cannot be replayed on another escrow, amount, asset, beneficiary or deadline.

## What it does not guarantee

- **Inclusion in the Midnight ledger** (Midnight lane): verifying the proof does not prove the transaction was finalized on Midnight; that would need a consensus light client. Root and policy are pinned on Stellar, so a proof made against another list is refused.
- **Truth of KYC data**: the PSAV that attested is responsible.
- **Snapshot freshness beyond the window**: mitigated by `min_issued_at` (admin bumps it when a new snapshot supersedes the old one) and `valid_until`.
- **Trusted setup**: development ceremony on testnet.

## Composability risks

- **Dependency upgrades**: `circom-verifier` and `midnight-verifier` are upgradeable by their admin; an upgrade changes what "valid" means. Mitigation (phase 1): pin the verifier wasm hash in the gate policy and refuse a mismatch.
- **Reentrancy**: escrow state is written before any token transfer; gate and verifiers are read-only; the token is a Stellar Asset Contract.
- **Admin keys**: testnet-only keys, never reused from production. Every policy change emits `policy_set`.

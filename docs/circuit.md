# Circuit and public signals

## Circom lane (phase 1)

`circuits/sanctions/sanctions_nonmembership.circom` proves that the beneficiary is **not** in the sanctions snapshot whose root the gate pinned, without revealing who the beneficiary is.

Public signals, in this exact order (enforced by `compliance-gate`):

| Index | Signal | Checked against |
| --- | --- | --- |
| 0 | `sanctions_root` | policy, pinned by admin |
| 1 | `pepper_commit` | policy (provider-signed commitment to the snapshot pepper) |
| 2 | `policy_hash` | policy (rule pack hash) |
| 3 | `context` | `compliance-escrow.context(id)` |
| 4 | `issued_at` | `>= policy.min_issued_at` |

The gate also refuses any proof once `ledger.timestamp > policy.valid_until`.

### Entry scheme (aligned with the Midnight TravelRuleGate v12)

Snapshot entries are `H(pepper, sha256(id))`, with a secret pepper per snapshot. Inside the circuit:

1. check `H(pepper) == pepper_commit` (pepper is a private input);
2. derive `key = H(pepper, sha256(id))` from the private identifier;
3. prove indexed-Merkle non-membership: a leaf `(value, next)` with `value < key < next` under `sanctions_root`.

So no unsalted, brute-forceable identifier hash (a CPF has about 10^9 values) is ever public. Credit for the indexed Merkle approach: ProofOrBluff (@realjohnny5i).

## Midnight lane (phases 2-3)

`midnight-verifier` will verify the TravelRuleGate's own proof (midnight-proofs: Plonk + KZG over BLS12-381, Blake2b transcript) against its pinned verifier key and statement. Measured building blocks (soroban-sdk 27.0.6 budget, 2026-11-23): G1 MSM of 44 points 67.2M instructions, 2-pair pairing 24.1M, cap 400M per transaction.

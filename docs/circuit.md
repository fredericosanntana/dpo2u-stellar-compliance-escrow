# Circuit and public signals

## Circom lane (phase 1)

`circuits/sanctions/main.circom` (`SanctionsNonMembership(16)`, 6,461 constraints, depth 16 = 65,536 leaves) proves that the beneficiary is **not** in the sanctions snapshot whose root the gate pinned, without revealing who the beneficiary is.

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
3. prove indexed-Merkle non-membership: a leaf `(value, next)` with `value < key < next` (keys truncated to 248 bits, canonical decomposition enforced) under the Merkle root;
4. bind the snapshot: `sanctions_root = H(merkle_root, pepper_commit, issued_at)`, so a prover cannot pair an old tree with a newer `issued_at`.

`policy_hash` and `context` are bound by dummy constraints, otherwise a Groth16 proof would be malleable on those signals.

So no unsalted, brute-forceable identifier hash (a CPF has about 10^9 values) is ever public. Credit for the indexed Merkle approach: ProofOrBluff (@realjohnny5i).

### Tooling and reproducibility

- `tools/sanctions-tree/build.mjs` builds the snapshot from `fixtures/sanctions-list.fictitious.json` (10 fictitious identifiers) and writes `circuits/sanctions/input.json`. All hashing goes through a compiled helper circuit (`tools/sanctions-tree/hasher`), so off-chain and in-circuit hashes cannot drift. The pepper stays in `fixtures/snapshot.secret.json` (gitignored). It exits with code 2 if the identifier is listed: no witness, no proof.
- `scripts/make-fixture-proof.sh <context>` regenerates `fixtures/proofs/sanctions/` with `ctg zk prove`.
- `contracts/compliance-escrow/tests/real_proof.rs` runs the real proof through the real verifier, gate and escrow: valid proof releases, tampered proof is rejected with funds locked, the same proof cannot release another escrow.

### Known limitations (phase 1)

- Dev trusted setup (`ctg zk build`, local ptau 14). A public ceremony is needed before any real use.
- Poseidon from circomlib 2.0.5 (GPL-3.0, dev dependency only) compiled with `-p bls12381`: the round constants are the BN254 ones reduced in the BLS12-381 field. It is a consistent but non-standard instance, not an audited parameter set.
- Sanctions data is fictitious; the provider signature over `(root, pepper_commit, issued_at)` is represented by the admin pinning the policy.

## Midnight lane (phases 2-3)

`midnight-verifier` will verify the TravelRuleGate's own proof (midnight-proofs: Plonk + KZG over BLS12-381, Blake2b transcript) against its pinned verifier key and statement. Measured building blocks (soroban-sdk 27.0.6 budget, 2026-11-23): G1 MSM of 44 points 67.2M instructions, 2-pair pairing 24.1M, cap 400M per transaction.

# Midnight proof verifier on Soroban (phase 2)

`contracts/midnight-verifier` verifies, inside a Soroban transaction, a proof made by Midnight's own proof system: `midnight-proofs` 0.8.2 through `midnight-zk-stdlib` 2.4.0. That is the stack the Midnight ledger (`midnight-ledger`, `transient-crypto`) uses: Plonk with permutation, lookup and trash arguments, KZG multi-open over BLS12-381, and a Blake2b transcript.

## Result

A real proof from the official prover (Poseidon preimage, k = 6, one lookup and one trashcan) is accepted by the Soroban contract running as wasm. The same proof is rejected when it is tampered with, when the statement changes, when the hints are swapped or one is added, and when a value is out of field.

| Measured (soroban-sdk 27.0.6 budget) | CPU instructions | Memory |
| --- | --- | --- |
| `verify` through the release wasm | 149,011,495 (37% of the 400M cap) | 2.67 MB |
| `verify` as native contract (host calls only) | 116,564,361 | 1.02 MB |

Wasm size: 77 KB. The SVK for this circuit is 7.7 KB; the proof is 2,912 bytes plus 22 hints.

## How it is built

| Piece | Role |
| --- | --- |
| `crates/midnight-verifier-core` | `no_std` verifier, generic over a `Backend` (field and curve operations). It mirrors `plonk::verifier::prepare`, `evaluate_identities`, `KZGCommitmentScheme::multi_prepare` and `DualMSM::check` step by step. |
| `tools/midnight-export` | Std tool on the real Midnight stack. It flattens a `VerifyingKey` into an SVK blob, proves, and checks the core verifier against `midnight_zk_stdlib::verify` with a native backend, on valid and tampered inputs. It writes `fixtures/midnight/<circuit>/`. |
| `contracts/midnight-verifier` | Soroban backend (host BLS12-381 functions) plus storage for SVKs, addressed by their sha256. |

The SVK carries everything the verifier needs: domain constants, the queries, the fixed and permutation commitments, the gate, lookup and trash expressions (as postfix bytecode), the transcript representative of the VK, and `[tau]_2` / `-[1]_2`. It also carries the **opening plan**. `construct_intermediate_sets` compares commitments by identity and points by rotation, so the grouping of queries into point sets depends only on the VK; the exporter computes it once.

### Compressed points and hints

Midnight proofs carry compressed G1 points (48 bytes). Soroban only takes uncompressed points and has no base-field arithmetic, so it cannot take a square root. The caller passes, for each non-identity point in reading order, its uncompressed form as a hint. The contract accepts a hint only if:

- its x equals the compressed x (flags masked);
- the sign flag of the compressed point agrees with y (y > (p − 1)/2);
- it is on the curve and in the subgroup (host check);
- every hint is used.

The transcript always absorbs the proof's own compressed bytes, so a hint can only reproduce what the proof says. `midnight-export` writes the hints; a relayer computes them the same way.

## Contract interface

- `register_vk(svk) -> vk_hash`: admin only. Stores the blob under its sha256 and emits `vk_registered`.
- `vk(vk_hash) -> Option<Bytes>`
- `verify(vk_hash, proof, hints, statement) -> bool`: `false` for any proof that does not verify. Errors: `UnknownVk`, `BadVk`, `ValueOutOfField`, `UnsupportedVk`.

## Trust model

A `true` means the statement satisfies the circuit behind the pinned VK. It does not mean the proof was accepted on the Midnight ledger; that would need a light client. The relayer only transports the proof and the hints. The admin who registers an SVK is trusted to export it from the right Midnight VK; the export is reproducible with `tools/midnight-export`, and the vk_hash pins the exact bytes.

## Limits and next steps

- The committed instance is fixed to the identity, as `midnight_zk_stdlib::verify(.., None, ..)` does, with one public instance column. Other shapes return `UnsupportedVk`.
- The cost grows with the number of commitments, queries and gate operations, not with k. Phase 3 measures a real TravelRuleGate (Compact) proof, which is a larger circuit than this Poseidon example. The gate's `check_midnight` lane is wired in phase 3.
- The verifier follows midnight-proofs 0.8.2 without `truncated-challenges`, as the ledger is built. A change of proof system version on Midnight needs a new export and possibly a new core.
- The SRS is the Filecoin one Midnight uses (`bls_filecoin_2p19`); `[tau]_2` is taken from it.

## Reproduce

```sh
# official proof + SVK + hints (needs SRS_DIR with bls_filecoin_2p19)
cd tools/midnight-export && SRS_DIR=... cargo run --release -- ../../fixtures/midnight
# Soroban, native and wasm
cargo build --release --target wasm32v1-none -p midnight-verifier
cargo test -p midnight-verifier -- --nocapture
```

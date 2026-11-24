# Midnight proof verifier on Soroban (phase 2)

`contracts/midnight-verifier` verifies, inside a Soroban transaction, a proof made by Midnight's own proof system: `midnight-proofs` 0.8.2 through `midnight-zk-stdlib` 2.4.0. That is the stack the Midnight ledger (`midnight-ledger`, `transient-crypto`) uses: Plonk with permutation, lookup and trash arguments, KZG multi-open over BLS12-381, and a Blake2b transcript.

## Result

A real proof from the official prover (Poseidon preimage, k = 6, one lookup and one trashcan) is accepted by the Soroban contract running as wasm. The same proof is rejected when it is tampered with, when the statement changes, when the hints are swapped or one is added, and when a value is out of field.

| Measured (soroban-sdk 27.0.6 budget) | CPU instructions | Memory |
| --- | --- | --- |
| `verify` through the release wasm (Poseidon, zk-stdlib) | 135,552,417 (34% of the 400M cap) | 2.69 MB |
| `verify` through the release wasm (ZKIR v3 `transient_hash`, ledger prover) | 161,255,183 (40%) | 2.84 MB |
| `verify` through the release wasm, **real TravelRuleGate v12 proof** (k=17, 417 statement values) | 312,864,758 (78%) | 6.06 MB |
| `verify` as native contract (host calls only) | 116,564,361 | 1.02 MB |

Wasm size: 91 KB (`opt-level = 3` for the verifier crates). The SVK for this circuit is 7.7 KB; the proof is 2,912 bytes plus 22 hints.

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

## Gate Midnight lane and escrow release (phase 3)

`compliance-gate` keeps a `MidnightPolicy` per `policy_id`, set by the admin with `set_midnight_policy` (event `midnight_policy_set`):

| Field | Meaning |
| --- | --- |
| `vk_hash` | sha256 of the SVK registered in `midnight-verifier` |
| `statement_len` | exact statement length of the circuit |
| `pins` | `(index, value)` pairs the statement must carry: sanctions root, rule-pack hash, gate address, as the circuit exposes them |
| `context_index` | statement index that must equal the escrow `context` (no replay on another escrow) |
| `valid_until` | the lane refuses proofs after this ledger time |

A Compact statement is `[binding_input, public transcript..]` (midnight-zkir `ir_vm.rs`), so the layout is circuit specific and lives in the policy, not in code. `check_midnight(policy_id, context, proof, hints, statement)` checks the length, the pins, the context and the expiry, then calls `midnight-verifier.verify`. `compliance-escrow.release_midnight(id, proof, hints, statement)` pays only if it passes; any refusal reverts and the escrow stays `Funded`.

End to end test (`contracts/compliance-escrow/tests/midnight_proof.rs`): a ZKIR v3 circuit proved with the ledger prover (`midnight-export zkir-context`) whose statement is `[binding_input, commitment, context]`, bound to `escrow.context(1)`. Real midnight-verifier, gate and escrow with a SAC as USDC: released, tampered proof and wrong context refused. `release_midnight` with the verifier as wasm: **161,933,352 CPU (40% of the cap), 3.0 MB**. This circuit stands in for the TravelRuleGate; the real gate proof plugs into the same lane with its own pins.

## Real TravelRuleGate proof (captured on preview)

`evaluateTransfer` (TravelRuleGate v12, compactc 0.36.0, ZKIR v3.1, `verifier-key[v7]`): k = 17, 9 advice, 37 fixed, 10 permutation columns, 6 lookups, 1 trashcan, 35 gates (931 ops), 5 point sets; proof 5,744 B; SVK 14,460 B. The core exports it without changes, and the captured proof (417 statement values, 39 hints) **verifies in the Soroban wasm: 312,864,758 CPU (78% of the 400M cap), 6.1 MB** (`contracts/midnight-verifier/tests/wasm_cost.rs`, fixture `fixtures/midnight/travel-rule-gate-v12`). The verifier crates are built with `opt-level = 3` (wasm 91 KB): the same proof cost 361M at `opt-level = "z"`. The largest costs are the 39 G1 subgroup checks of the hints (92.8M), the final MSM (65.6M), wasm execution (63.0M) and field conversions of the statement (22.7M).

The `/prove` request carries every private witness (including the contract owner secret, because the circuit starts with `assert_owner()`), so it is never published. The statement is public: `[binding_input, communications_commitment, public transcript..]`, all of which appear in the Midnight transaction. `midnight-export statement <request> <response> <pi.hex>` runs where the request is, proves once locally to get the statement in the ledger's order, and writes `pi.hex` only after the captured proof verifies against it. `midnight-export captured` then builds the SVK, hints and checks from the public files.

## Trust model

A `true` means the statement satisfies the circuit behind the pinned VK. It does not mean the proof was accepted on the Midnight ledger; that would need a light client. The relayer only transports the proof and the hints. The admin who registers an SVK is trusted to export it from the right Midnight VK; the export is reproducible with `tools/midnight-export`, and the vk_hash pins the exact bytes.

## Limits and next steps

- The committed instance is fixed to the identity, as `midnight_zk_stdlib::verify(.., None, ..)` does, with one public instance column. Other shapes return `UnsupportedVk`.
- The cost grows with the number of commitments, queries and gate operations, not with k. Phase 3 measures a real TravelRuleGate (Compact) proof, which is a larger circuit than this Poseidon example. The gate's `check_midnight` lane is wired in phase 3.
- The verifier follows midnight-proofs 0.8.2 without `truncated-challenges`, as the ledger is built. A change of proof system version on Midnight needs a new export and possibly a new core.
- The SRS is Midnight's own (`bls_midnight_2p{k}`, as the proof server uses), not the Filecoin one: a proof from the ledger prover only verifies against Midnight's `[tau]_2`. The tool reads `MIDNIGHT_PARAMS_DIR` and falls back to the `bls_midnight_2p14` bundled in `midnight-transient-crypto`.

## Reproduce

```sh
# official proof + SVK + hints (Midnight SRS; k <= 14 needs nothing else)
cd tools/midnight-export
cargo run --release -- poseidon ../../fixtures/midnight
cargo run --release -- zkir-selftest ../../fixtures/midnight   # ledger prover (ZKIR v2) pipeline
cargo run --release -- compact <name> <ir> <prover> <verifier> <preimage> ../../fixtures/midnight
# Soroban, native and wasm
cargo build --release --target wasm32v1-none -p midnight-verifier
cargo test -p midnight-verifier -- --nocapture
```

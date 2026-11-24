# Cost analysis

Filled with `ctg estimate deploy` / `ctg estimate verify` output once the testnet deploy runs (phase 1).

## Phase 1 measured (local budget, real proof)

`compliance-escrow.release` with a real 5-signal Groth16 proof (gate checks + circom-verifier + SAC transfer): **55,091,913 CPU instructions**, about 14% of the 400M cap.

## Phase 2 measured (real Midnight proof)

`midnight-verifier.verify` with a real midnight-zk-stdlib 2.4.0 proof (Poseidon preimage, k=6), through the release wasm: **149,011,495 CPU instructions** (37% of the cap), 2.67 MB memory. Details in `docs/midnight-verifier.md`.

## Measured building blocks (2026-11-23, soroban-sdk 27.0.6 budget, local)

| Operation | CPU instructions |
| --- | --- |
| G1 MSM, 44 points | 67,211,046 |
| G1 MSM, 64 points | 96,650,635 |
| G1 MSM, 100 points | 149,641,894 |
| Pairing check, 2 pairs | 24,063,381 |
| 1,000 Fr mul+add (host) | 16,278,756 |

Transaction cap: 400M instructions. Groth16 reference (Caatinga docs, testnet): 43.1M with 1 public signal, about +3.56M per extra signal; this circuit has 5.

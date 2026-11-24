# Cost analysis

Filled with `ctg estimate deploy` / `ctg estimate verify` output once the testnet deploy runs (phase 1).

## Measured building blocks (2026-11-23, soroban-sdk 27.0.6 budget, local)

| Operation | CPU instructions |
| --- | --- |
| G1 MSM, 44 points | 67,211,046 |
| G1 MSM, 64 points | 96,650,635 |
| G1 MSM, 100 points | 149,641,894 |
| Pairing check, 2 pairs | 24,063,381 |
| 1,000 Fr mul+add (host) | 16,278,756 |

Transaction cap: 400M instructions. Groth16 reference (Caatinga docs, testnet): 43.1M with 1 public signal, about +3.56M per extra signal; this circuit has 5.

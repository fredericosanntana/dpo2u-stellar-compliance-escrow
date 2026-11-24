# Real TravelRuleGate v12 proof (Midnight preview)

Circuit `evaluateTransfer` of TravelRuleGate v12 (`fredericosanntana/dpo2u-midnight@10b135c`, compactc
0.36.0, ZKIR v3.1), proved by `midnightntwrk/proof-server:9.0.1` for one PASS evaluate on Midnight
preview (shared gate `61292c31…16fe`, block 244701). Source: branch `data/escrow-fase3-midnight`
@ `236b4a74`, `fixtures/midnight/`.

| File | What |
| --- | --- |
| `ledger.verifier` | the ledger's `verifier-key[v7]` (sha256 `e97cb00c…a1fd6`, same bytes as `evaluateTransfer.verifier`) |
| `proof-response.bin` | proof-server response (`proof-versioned`), sha256 `54ef13bf…24b2` |
| `pi.hex` | public statement, 417 field elements (LE hex), sha256 `9197b0f2…bc7d` |
| `vk.svk`, `proof.bin`, `hints.hex` | made by `midnight-export captured travel-rule-gate-v12 ...` |

The statement is `[binding_input, communications_commitment, public transcript..]`: values that are
public in the Midnight transaction. The `/prove` request (private witnesses, including the contract
owner secret) is not published; `pi.hex` was derived from it offline with `midnight-export statement`,
which only writes it after the captured proof verifies. Snapshot, pepper and transfer data are
fictitious; no personal data.

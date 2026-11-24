# TravelRuleGate v12 proof bound to a Stellar testnet DvP trade

PASS `evaluateTransfer` on the Midnight preview shared v12 gate
`61292c3188a5cdd22aa225be140977ca27bbc847a10723d23512a9550ebe16fe`, with
`transfer_id = compliance-dvp.context(1)` of `CBXIFUYO54NEY7PAAQOKWXFA2Z77BAKSDRVWZ7B7S43QGHG4I5XDGWVE`
(gate `CDF3F3XCMDIYLGC46JK5IMBQBIM657SEQ6PCUMIOORWVVIQ4OQ2523MG`, policy_id 2). Trade 1: 10 DPOSEC (test
security, issuer `GCV5T3PKJPZIIWHMVUQWBNA3LHXPTLZGPWNTDOZRGG5M7YFMRSCVQICN` with AUTH_REVOCABLE, SAC
`CB6YLZYHWW5CLY4E3YIGRN7HNM3DVG2QKVCFMIGK2LWVFV2ATJYNC5ZX`) for 250 testnet USDC.

- context (BE): `00977ba13d51cd64f08cc2c230fe3c7382c86ba74c12d0a73ea436460d82f446`
- Midnight tx identifier `00400f00f7fa897927263e3b6e6357618829343bbb187c8c86fbe6ad55bceb2aec`, preview block 251180; status 1, reason 0.
- Disposable snapshot and pepper, created only for this capture (fictitious).

| File | Bytes | sha256 |
| --- | --- | --- |
| `pi.hex` | 27104 | `c268f271c2de19150279c12dffc80e5e1549d320e0d696d8078b692c12ebf782` |
| `proof.bin` | 5744 | `ccb85197ef4e3263db01d292667e1cebcbfb1e34d91c9e78bd0250799ea26e05` |
| `hints.hex` | 7526 | `fb11d34eacc7153b2755a6df3e20076f0534ab3de26d4c6e399bbb95bba5d364` |
| `proof-response.bin` | 5772 | `fd6c36007e3f3314d630d75cb77bf1f81e7eaa0698f5f1b90b61e8337bc80deb` |

Same flow and checks as `escrow-bound/`: statement offline (the captured proof verifies), proof and 39 hints from
`midnight-export captured` (SVK byte-identical to the registered one), context at 202/203, status 1 at 208,
fail_reason 0 at 228, no owner secret and no capture pepper in any encoding. The request was deleted.

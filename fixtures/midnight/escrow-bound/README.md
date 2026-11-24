# TravelRuleGate v12 proof bound to a Stellar testnet escrow

PASS `evaluateTransfer` on the Midnight preview shared v12 gate
`61292c3188a5cdd22aa225be140977ca27bbc847a10723d23512a9550ebe16fe`, with
`transfer_id = escrow.context(1)` of the testnet escrow `CBHZIEWBIJC7VYU43NTFZT44IBLAPZT3MYLJZXIGXG3ZQJNIN6UJ7CDU`
(gate `CDF3F3XCMDIYLGC46JK5IMBQBIM657SEQ6PCUMIOORWVVIQ4OQ2523MG`, midnight-verifier
`CDRVMZMAB4HGSEXRST6KQAO7USVLXPON5YIVLSL4ENVJCGQ5L5PBCWBU`, vk_hash
`879336d7478b1b686211d1a055caff8c054434e9b8e61e0b69435b654a810fa5`).

- context (BE): `00592cfd012267b0b5c5cbada2d5fede666e1966d4cfe6ab6e7462626da3118f`
- Midnight tx identifier `00ba80c550d57bbe044b16b431e3628806ab99574a4a82d22d69a7efe01b783d1b`, preview block 246649; verdict status 1, reason 0.
- Disposable snapshot and pepper, created only for this capture (fictitious).

| File | Bytes | sha256 |
| --- | --- | --- |
| `pi.hex` | 27104 | `97c26a87fff12034d69148bf5a5e78f435b3ddd7331ea436345fc4eaf9b01a65` |
| `proof-response.bin` | 5772 | `ae8078ebb66b2b89dcb938142934268160788af53721730b3d3aa0d5442832f1` |
| `proof.bin` | 5744 | `f54f9240743149646538b2069625233be02c1931752f87919775cae3e2079206` |
| `hints.hex` | 7526 | `a7ee490c42e78a267b45fffa579b83cf82eb1913f79d6ab1aa7aae60cc6511ac` |

`pi.hex` from `midnight-export statement` (offline; the captured proof verifies). `proof.bin` and `hints.hex`
(39 hints) from `midnight-export captured` on the public files; its SVK is byte-identical to the
registered one. In the statement the context sits at lines 202/203 (and 27/28) as `[ctx[31], LE(ctx[0..30])]`,
status 1 at 208, fail_reason 0 at 228. Checked before publishing: no owner secret and no capture
pepper in any encoding (raw and 8-byte fragments both orders, hex text, field element mod r and
31 + 1 split, 64-value bit runs). The request was deleted.

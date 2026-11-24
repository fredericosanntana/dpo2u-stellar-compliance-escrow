# Demo video script (about 3 minutes)

Screen recording plus voice. Every number and hash below is real and comes from testnet, from preview or from the test output in this repo. Testnet only: say it on screen once.

| # | Time | Screen | Voice |
| --- | --- | --- | --- |
| 1 | 0:00-0:20 | Title: "Compliance as a protocol on Stellar". Diagram: Midnight decides, Stellar settles | "A regulated transfer has to prove three things at once: data protection, the Travel Rule and the securities rules. Today you either expose personal data or trust someone who says they checked. We prove it instead." |
| 2 | 0:20-0:45 | `docs/cvm-package.md`, the "Who checks what" table | "The case is a receivable token in the style of CVM Resolution 88. The investor buys 10 units for 250 USDC. The issuer controls who may hold the token. Sanctions, the Travel Rule and the rule pack are proven on Midnight, privately." |
| 3 | 0:45-1:15 | Terminal: Midnight preview `evaluateTransfer` with `transfer_id` = escrow context; then the PASS verdict | "On Midnight, the TravelRuleGate checks the beneficiary against a keyed sanctions snapshot and checks the Travel Rule data, without revealing any of it. The transfer id is the escrow's own context, so this proof belongs to one trade only." |
| 4 | 1:15-1:45 | stellar.expert: `release_midnight` tx `ef3e413f…bf30`; events verdict pass=true, transfer 1 USDC, released | "On Stellar, our Soroban contract verifies the native Midnight proof itself: Plonk with KZG over BLS12-381, 313 million instructions, under the 400 million cap. No relayer trust, no bridge. The gate pins the rule pack, the list and a PASS verdict. Only then is the USDC released." |
| 5 | 1:45-2:15 | `cargo test -p compliance-dvp -- --nocapture`: DvP settles at 162M CPU, and the frozen investor is refused | "For securities, delivery versus payment: the token and the cash change hands in the same call, or neither does. If the issuer freezes the investor, a valid proof is not enough and the settlement reverts." |
| 6 | 2:15-2:40 | `docs/compliance-and-risk.md` and the data-protection notes | "Data protection is not a box we tick at the end. It decides how everything else is proven. On chain there are only commitments, proofs and pseudonymous addresses. Erasure happens at the provider, and the proof that remains identifies no one." |
| 7 | 2:40-3:00 | README, testnet table and repo link | "Testnet, open source, built with Caatinga. DPO2U: compliance as a protocol." |

## Recording checklist

- Use testnet and preview only. Show no secret keys, seeds or `.env` files, and no terminal history that contains them.
- Use the escrow-bound fixtures (`fixtures/midnight/escrow-bound/`) and the tx hashes in the README.
- Keep each terminal command short and show its output.
- Show no names or CPFs, not even fictitious ones. The snapshot ids are opaque hashes.

# CVM package: compliant delivery versus payment

This package shows how a tokenized security changes hands on Stellar only when the compliance evidence is there, and without putting personal data on chain. It is a testnet prototype. The legal mapping below is DPO2U's reading of the rules and must be reviewed by counsel before any real offering.

## The case

An issuer has tokenized receivables in the style of a **CVM Resolution 88** offering (crowdfunding of small businesses). An investor buys 10 units for 250 USDC. Three things must hold at the moment of settlement:

1. **The investor may hold the security.** The issuer, or the platform acting for it, controls the holder list.
2. **The transfer is compliant.** The investor is not sanctioned, the Travel Rule data was exchanged between the service providers, and the rule pack in force was applied.
3. **Personal data stays private** (LGPD/GDPR). Nobody on Stellar learns who the investor is, beyond a pseudonymous address.

`compliance-dvp` settles both legs in one call: the security goes to the buyer and the cash to the seller, or nothing moves.

## Who checks what

| Requirement | Basis (to be reviewed by counsel) | Enforced by | Evidence on Stellar |
| --- | --- | --- | --- |
| Data minimization, purpose, security, international transfer, data-subject rights | LGPD arts. 6, 7, 18, 33, 38, 46, 48; GDPR for flows abroad | The whole design: identifiers stay with the service provider and in Midnight private state; on chain only commitments, proofs and pseudonymous addresses | Nothing personal; a statement of public values (hashes, verdict, ids) |
| Holder eligibility (who may hold the security) | Res. CVM 88/2022 (platform duties, investor limits); Res. CVM 30/2021 (suitability) | The security token: a Stellar Asset with `AUTH_REVOCABLE`/authorization flags, so the issuer authorizes or freezes each holder | A refused transfer reverts the settlement |
| Sanctions screening and AML | Lei 9.613/1998; Lei 13.810/2019 (UN sanctions); Res. CVM 50/2021 | Midnight TravelRuleGate v12: keyed non-membership proof against a provider-signed snapshot | `list_root`, `pepper_commit` and `provider_id` pinned in the gate policy |
| Travel Rule | FATF R.16; BCB Res. 519-521/2025 | TravelRuleGate: originator and beneficiary data proven present and consistent; disclosed only to the counterparty provider | Verdict `status = PASS`, `fail_reason = 0` pinned |
| Crypto-asset service providers and securities nature | Lei 14.478/2022; BCB Res. 519-521/2025; Parecer de Orientação CVM 40/2022 | Gate policy is set by the operator's admin; every change is an on-chain event | `policy_hash` of the rule pack pinned |
| One proof, one trade | Integrity of the settlement | `context` = sha256 of contract, trade id, seller, buyer, both assets, both amounts, deadline, policy; used as the Midnight `transfer_id` | Statement positions 202/203 must equal the trade context |

What the token cannot see (sanctions, Travel Rule, the rule pack) the gate proves. What the gate cannot know (whether this investor may still hold this security today) the issuer controls on the token. Both must agree in the same transaction.

## Flow

1. The seller calls `offer`, which locks the 10 units, names the buyer and sets the price, deadline and policy.
2. The buyer calls `fund`, which locks the 250 USDC.
3. The buyer's service provider (an agent) evaluates the transfer on Midnight with `transfer_id = dvp.context(id)`. The TravelRuleGate checks sanctions and the Travel Rule privately and writes a PASS verdict.
4. A relayer submits the proof, the hints and the public statement to `settle_midnight`. Anyone may relay, and nobody can forge a proof.
5. The gate checks the statement against the pinned policy, `midnight-verifier` checks the proof, and the token checks that the buyer is authorized. Both legs then move.
6. If the deadline passes without settlement, `cancel` returns each leg to its owner.

## What is shown in the tests

- `contracts/compliance-dvp/src/test.rs`: settlement moves both legs. A refused proof, a proof made for another trade and an expired trade move nothing. An investor frozen by the issuer reverts the settlement even with a valid proof. `cancel` returns both legs.
- `contracts/compliance-dvp/tests/midnight_dvp.rs`: a real Midnight proof (ledger prover) bound to the trade context settles the trade through the wasm verifier at **162.2M CPU** (41% of the cap). The frozen investor is refused first.
- The real TravelRuleGate v12 proof costs 313M CPU in the verifier, and the escrow release with it cost 328.5M on testnet. A DvP settlement with it adds one more token transfer.

## Data-protection notes for the operator

- **Roles.** The issuer, the platform and each service provider are controllers or processors of investor data under the LGPD. The validators of Stellar and Midnight process no personal data in this design.
- **DPIA (RIPD).** Records that identifiers never leave the providers, that the sanctions list is keyed per snapshot (no reversible hash of a CPF), and that a Travel Rule disclosure goes only to the counterparty provider.
- **Erasure.** On-chain data identifies no one. Erasure is done by deleting the data and the salts at the provider and in Midnight private state.
- **Supervisor access.** An authorized supervisor can receive the selective disclosure from Midnight. That access is logged and recorded in the DPIA.

## Not covered yet

- Offering limits per investor and per issuer (Res. CVM 88) are the platform's job, enforced through holder authorization. They are not proven in circuit.
- The verdict's `issued_at` and `valid_until` are not yet compared with Stellar ledger time. The policy's own `valid_until` bounds it.
- Proof of inclusion in the Midnight ledger (light client) is out of scope. See [threat-model.md](threat-model.md).

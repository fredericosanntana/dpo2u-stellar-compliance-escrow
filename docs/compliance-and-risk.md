# Compliance and risk assumptions

A transfer is released only when four layers pass together. Data protection is not a separate box: it decides **how** the other three are proven (no personal data on-chain).

| Layer | Legal basis (to be reviewed by counsel) | Protocol rule | Where |
| --- | --- | --- | --- |
| Data protection | LGPD (Lei 13.709/2018): minimization and purpose (art. 6), legal basis (art. 7, II), international transfer (art. 33), data-subject rights (art. 18), security (art. 46), incident notice (art. 48), DPIA/RIPD (art. 38); GDPR for global flows | No personal data or reversible hash on-chain: only commitments and proofs. Identifiers stay with the PSAV and in Midnight private state | Midnight, PSAV |
| Travel Rule | FATF Recommendation 16; BCB Resolutions 519-521/2025 | Originator/beneficiary data proven present and consistent; disclosed only to the counterparty PSAV | Midnight TravelRuleGate |
| Sanctions and AML | Lei 9.613/1998; Lei 13.810/2019; Resolução CVM 50/2021 | Indexed-Merkle non-membership proof against a provider-signed snapshot, pinned root and freshness window | Midnight and Soroban (same statement) |
| PSAV and securities | Lei 14.478/2022; BCB Resolutions 519-521/2025; Parecer de Orientação CVM 40/2022; Resoluções CVM 88/2022 and 30/2021 | Only authorized PSAVs and eligible investors; escrow and DvP deliver the asset only with the proof, and the security's issuer still authorizes each holder (see [cvm-package.md](cvm-package.md)) | Soroban escrow, `compliance-dvp`, token flags |

## Data-protection decisions the code follows

- **No reversible identifier hashes.** Sanctions entries use `H(pepper, sha256(id))` with a per-snapshot secret pepper (see [circuit.md](circuit.md)).
- **Immutability vs. erasure (LGPD art. 18).** Nothing on Stellar identifies the data subject; erasure is honored by deleting data and salts at the PSAV and in Midnight private state. The proof that remains identifies no one.
- **International transfer.** A BR → MX remittance relies on LGPD art. 33 (standard contractual clauses between PSAVs, Resolução CD/ANPD 19/2024); the protocol transmits only the Travel Rule minimum.
- **Versioned policy.** Every rule pack has a `policy_hash`; changing a rule changes the hash and the gate refuses proofs for the old one.

## Risk assumptions

- Testnet only; fictitious sanctions list and identities; no real funds.
- KYC truth is the attesting PSAV's responsibility; the proof covers the rule, not the truth of the data.
- Beneficiary Stellar addresses are on-chain by necessity (payment); they are pseudonymous and never linked to identity on-chain.
- Development trusted setup for Groth16 (Caatinga dev ceremony) — not for production.

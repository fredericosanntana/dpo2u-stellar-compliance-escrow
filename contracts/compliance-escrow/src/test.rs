#![cfg(test)]
extern crate std;

use super::*;
use compliance_gate::{
    testutils::{policy, proof as gate_proof, signals, MockVerifier, MockVerifierClient},
    ComplianceGate, ComplianceGateClient,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Env,
};

struct Setup<'a> {
    env: Env,
    escrow: ComplianceEscrowClient<'a>,
    gate: ComplianceGateClient<'a>,
    mock: MockVerifierClient<'a>,
    usdc: TokenClient<'a>,
    payer: Address,
    beneficiary: Address,
}

fn setup<'a>() -> Setup<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(5_000);
    let admin = Address::generate(&env);

    // Testnet-style USDC as a Stellar Asset Contract.
    let issuer = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(issuer);
    let usdc = TokenClient::new(&env, &sac.address());
    let payer = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&payer, &1_000_0000000);

    let mock_id = env.register(MockVerifier, ());
    let mock = MockVerifierClient::new(&env, &mock_id);
    mock.set_result(&true);
    let gate_id = env.register(
        ComplianceGate,
        (admin.clone(), mock_id, Address::generate(&env)),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);
    gate.set_policy(&1, &policy(&env));

    let escrow_id = env.register(ComplianceEscrow, (admin, gate_id));
    let escrow = ComplianceEscrowClient::new(&env, &escrow_id);
    let beneficiary = Address::generate(&env);
    Setup {
        env,
        escrow,
        gate,
        mock,
        usdc,
        payer,
        beneficiary,
    }
}

fn p(s: &Setup) -> Proof {
    let g = gate_proof(&s.env);
    Proof {
        a: g.a,
        b: g.b,
        c: g.c,
    }
}

fn deposit(s: &Setup, amount: i128) -> u64 {
    s.escrow.deposit(
        &s.payer,
        &s.beneficiary,
        &s.usdc.address,
        &amount,
        &8_000,
        &1,
    )
}

#[test]
fn pass_releases_to_beneficiary() {
    let s = setup();
    let id = deposit(&s, 100_0000000);
    assert_eq!(s.usdc.balance(&s.escrow.address), 100_0000000);
    let ctx = s.escrow.context(&id);
    let sig = signals(&s.env, &s.gate.policy(&1), &ctx, 2_000);
    s.escrow.release(&id, &p(&s), &sig);
    assert_eq!(s.usdc.balance(&s.beneficiary), 100_0000000);
    assert_eq!(s.usdc.balance(&s.escrow.address), 0);
    assert_eq!(s.escrow.get(&id).state, State::Released);
    // Cannot be released or refunded twice.
    assert_eq!(
        s.escrow.try_release(&id, &p(&s), &sig),
        Err(Ok(Error::NotFunded))
    );
    assert_eq!(s.escrow.try_refund(&id), Err(Ok(Error::NotRefundable)));
}

#[test]
fn invalid_proof_reverts_and_keeps_funds_locked() {
    let s = setup();
    let id = deposit(&s, 50_0000000);
    s.mock.set_result(&false);
    let ctx = s.escrow.context(&id);
    let sig = signals(&s.env, &s.gate.policy(&1), &ctx, 2_000);
    assert!(s.escrow.try_release(&id, &p(&s), &sig).is_err());
    assert_eq!(s.escrow.get(&id).state, State::Funded);
    assert_eq!(s.usdc.balance(&s.escrow.address), 50_0000000);
    assert_eq!(s.usdc.balance(&s.beneficiary), 0);
}

#[test]
fn proof_for_one_escrow_cannot_release_another() {
    let s = setup();
    let a = deposit(&s, 10_0000000);
    let b = deposit(&s, 10_0000000);
    let sig_a = signals(&s.env, &s.gate.policy(&1), &s.escrow.context(&a), 2_000);
    assert!(s.escrow.try_release(&b, &p(&s), &sig_a).is_err());
    assert_eq!(s.escrow.get(&b).state, State::Funded);
}

#[test]
fn refund_only_after_deadline() {
    let s = setup();
    let id = deposit(&s, 25_0000000);
    assert_eq!(s.escrow.try_refund(&id), Err(Ok(Error::NotRefundable)));
    s.env.ledger().set_timestamp(8_001);
    let sig = signals(&s.env, &s.gate.policy(&1), &s.escrow.context(&id), 2_000);
    assert_eq!(
        s.escrow.try_release(&id, &p(&s), &sig),
        Err(Ok(Error::Expired))
    );
    s.escrow.refund(&id);
    assert_eq!(s.usdc.balance(&s.payer), 1_000_0000000);
    assert_eq!(s.escrow.get(&id).state, State::Refunded);
}

#[test]
fn deposit_validates_input_and_needs_payer_auth() {
    let s = setup();
    assert_eq!(
        s.escrow
            .try_deposit(&s.payer, &s.beneficiary, &s.usdc.address, &0, &8_000, &1),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        s.escrow
            .try_deposit(&s.payer, &s.beneficiary, &s.usdc.address, &1, &5_000, &1),
        Err(Ok(Error::InvalidDeadline))
    );
    deposit(&s, 1);
    // The payer is the one who authorized the deposit (and the SAC transfer under it).
    assert_eq!(s.env.auths()[0].0, s.payer);
}

#[test]
fn context_changes_with_every_bound_field() {
    let s = setup();
    let a = deposit(&s, 10);
    let b = deposit(&s, 11);
    assert_ne!(s.escrow.context(&a), s.escrow.context(&b));
    // First byte is zero: always inside the BLS12-381 scalar field.
    assert_eq!(s.escrow.context(&a).to_be_bytes().get(0), Some(0));
}

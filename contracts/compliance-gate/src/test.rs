#![cfg(test)]
extern crate std;

use super::*;
use crate::testutils::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, U256,
};

struct Setup<'a> {
    env: Env,
    gate: ComplianceGateClient<'a>,
    mock: MockVerifierClient<'a>,
    policy: Policy,
}

fn setup<'a>() -> Setup<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(5_000);
    let admin = Address::generate(&env);
    let mock_id = env.register(MockVerifier, ());
    let mock = MockVerifierClient::new(&env, &mock_id);
    mock.set_result(&true);
    let midnight = Address::generate(&env);
    let gate_id = env.register(ComplianceGate, (admin, mock_id, midnight));
    let gate = ComplianceGateClient::new(&env, &gate_id);
    let policy = policy(&env);
    gate.set_policy(&1, &policy);
    Setup {
        env,
        gate,
        mock,
        policy,
    }
}

#[test]
fn accepts_matching_fresh_valid_proof() {
    let s = setup();
    let ctx = u(&s.env, 42);
    let sig = signals(&s.env, &s.policy, &ctx, 2_000);
    assert!(s.gate.check_circom(&1, &ctx, &proof(&s.env), &sig));
}

#[test]
fn rejects_invalid_proof() {
    let s = setup();
    s.mock.set_result(&false);
    let ctx = u(&s.env, 42);
    let sig = signals(&s.env, &s.policy, &ctx, 2_000);
    let r = s.gate.try_check_circom(&1, &ctx, &proof(&s.env), &sig);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn rejects_proof_for_another_escrow() {
    let s = setup();
    let sig = signals(&s.env, &s.policy, &u(&s.env, 42), 2_000);
    let r = s
        .gate
        .try_check_circom(&1, &u(&s.env, 43), &proof(&s.env), &sig);
    assert_eq!(r, Err(Ok(Error::ContextMismatch)));
}

#[test]
fn rejects_other_sanctions_list_or_policy() {
    let s = setup();
    let ctx = u(&s.env, 42);
    let mut other = s.policy.clone();
    other.sanctions_root = u(&s.env, 0xDEAD);
    let r = s.gate.try_check_circom(
        &1,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &other, &ctx, 2_000),
    );
    assert_eq!(r, Err(Ok(Error::RootMismatch)));

    let mut other = s.policy.clone();
    other.pepper_commit = u(&s.env, 0xDEAD);
    let r = s.gate.try_check_circom(
        &1,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &other, &ctx, 2_000),
    );
    assert_eq!(r, Err(Ok(Error::PepperCommitMismatch)));

    let mut other = s.policy.clone();
    other.policy_hash = u(&s.env, 0xDEAD);
    let r = s.gate.try_check_circom(
        &1,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &other, &ctx, 2_000),
    );
    assert_eq!(r, Err(Ok(Error::PolicyHashMismatch)));
}

#[test]
fn rejects_stale_snapshot_and_expired_policy() {
    let s = setup();
    let ctx = u(&s.env, 42);
    let r = s.gate.try_check_circom(
        &1,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &s.policy, &ctx, 999),
    );
    assert_eq!(r, Err(Ok(Error::StaleSnapshot)));

    s.env.ledger().set_timestamp(10_001);
    let r = s.gate.try_check_circom(
        &1,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &s.policy, &ctx, 2_000),
    );
    assert_eq!(r, Err(Ok(Error::PolicyExpired)));
}

#[test]
fn rejects_wrong_signal_count_and_unknown_policy() {
    let s = setup();
    let ctx = u(&s.env, 42);
    let mut sig = signals(&s.env, &s.policy, &ctx, 2_000);
    sig.pop_back();
    let r = s.gate.try_check_circom(&1, &ctx, &proof(&s.env), &sig);
    assert_eq!(r, Err(Ok(Error::BadSignalCount)));
    let r = s.gate.try_check_circom(
        &7,
        &ctx,
        &proof(&s.env),
        &signals(&s.env, &s.policy, &ctx, 2_000),
    );
    assert_eq!(r, Err(Ok(Error::UnknownPolicy)));
}

#[test]
fn set_policy_requires_admin_and_field_values() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let gate_id = env.register(
        ComplianceGate,
        (
            admin.clone(),
            Address::generate(&env),
            Address::generate(&env),
        ),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);
    // No auth mocked: must fail.
    assert!(gate.try_set_policy(&1, &policy(&env)).is_err());

    env.mock_all_auths();
    let mut p = policy(&env);
    p.policy_hash = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &[0xFFu8; 32]));
    assert_eq!(gate.try_set_policy(&1, &p), Err(Ok(Error::ValueOutOfField)));
    gate.set_policy(&1, &policy(&env));
    assert_eq!(env.auths()[0].0, admin);
}

#[test]
fn midnight_lane_is_explicitly_not_implemented() {
    let s = setup();
    assert_eq!(
        s.gate.try_check_midnight(&1, &u(&s.env, 1)),
        Err(Ok(Error::MidnightLaneNotImplemented))
    );
}

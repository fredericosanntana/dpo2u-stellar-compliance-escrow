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
    midnight: MockMidnightClient<'a>,
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
    let midnight_id = env.register(MockMidnight, ());
    let midnight = MockMidnightClient::new(&env, &midnight_id);
    midnight.set_result(&true);
    let gate_id = env.register(ComplianceGate, (admin, mock_id, midnight_id));
    let gate = ComplianceGateClient::new(&env, &gate_id);
    let policy = policy(&env);
    gate.set_policy(&1, &policy);
    gate.set_midnight_policy(&1, &midnight_policy(&env));
    Setup {
        env,
        gate,
        mock,
        midnight,
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

fn statement(env: &Env, binding: u128, policy_hash: u128, ctx: &U256) -> soroban_sdk::Vec<U256> {
    let mut v = soroban_sdk::Vec::new(env);
    v.push_back(u(env, binding));
    v.push_back(u(env, policy_hash));
    v.push_back(ctx.clone());
    v
}

fn midnight_check(s: &Setup, ctx: &U256, st: &soroban_sdk::Vec<U256>) -> Result<bool, Error> {
    let proof = soroban_sdk::Bytes::new(&s.env);
    let hints = soroban_sdk::Vec::new(&s.env);
    match s.gate.try_check_midnight(&1, ctx, &proof, &hints, st) {
        Ok(Ok(v)) => Ok(v),
        Err(Ok(e)) => Err(e),
        other => panic!("{other:?}"),
    }
}

#[test]
fn midnight_lane_accepts_pinned_statement_with_context() {
    let s = setup();
    let ctx = u(&s.env, 77);
    assert_eq!(
        midnight_check(&s, &ctx, &statement(&s.env, 5, 0xA4, &ctx)),
        Ok(true)
    );
}

#[test]
fn midnight_lane_rejects_mismatches_and_invalid_proof() {
    let s = setup();
    let ctx = u(&s.env, 77);
    let ok = statement(&s.env, 5, 0xA4, &ctx);
    assert_eq!(
        midnight_check(&s, &ctx, &statement(&s.env, 5, 0xA5, &ctx)),
        Err(Error::PinMismatch)
    );
    assert_eq!(
        midnight_check(&s, &u(&s.env, 78), &ok),
        Err(Error::ContextMismatch)
    );
    let mut short = ok.clone();
    short.pop_back();
    assert_eq!(midnight_check(&s, &ctx, &short), Err(Error::BadSignalCount));
    s.midnight.set_result(&false);
    assert_eq!(midnight_check(&s, &ctx, &ok), Err(Error::InvalidProof));
    s.midnight.set_result(&true);
    s.env.ledger().set_timestamp(10_001);
    assert_eq!(midnight_check(&s, &ctx, &ok), Err(Error::PolicyExpired));
}

#[test]
fn midnight_policy_is_validated_and_admin_only() {
    let s = setup();
    let mut p = midnight_policy(&s.env);
    p.context_index = 3;
    assert_eq!(
        s.gate.try_set_midnight_policy(&2, &p),
        Err(Ok(Error::BadMidnightPolicy))
    );
    let mut p = midnight_policy(&s.env);
    p.context_index = 1; // collides with a pin
    assert_eq!(
        s.gate.try_set_midnight_policy(&2, &p),
        Err(Ok(Error::BadMidnightPolicy))
    );
    let mut p = midnight_policy(&s.env);
    p.context_encoding = CTX_COMPACT_BYTES32; // needs indices 2 and 3
    assert_eq!(
        s.gate.try_set_midnight_policy(&2, &p),
        Err(Ok(Error::BadMidnightPolicy))
    );
    let mut p = midnight_policy(&s.env);
    p.context_encoding = 7;
    assert_eq!(
        s.gate.try_set_midnight_policy(&2, &p),
        Err(Ok(Error::BadMidnightPolicy))
    );
    assert_eq!(
        s.gate.try_midnight_policy(&9),
        Err(Ok(Error::UnknownMidnightPolicy))
    );
    let env = Env::default();
    let admin = Address::generate(&env);
    let gate_id = env.register(
        ComplianceGate,
        (admin, Address::generate(&env), Address::generate(&env)),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);
    assert!(gate
        .try_set_midnight_policy(&1, &midnight_policy(&env))
        .is_err());
}

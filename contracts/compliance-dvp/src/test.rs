extern crate std;

use super::*;
use compliance_gate::{
    testutils::{policy, proof as gate_proof, signals, MockVerifier, MockVerifierClient},
    ComplianceGate, ComplianceGateClient,
};
use soroban_sdk::{
    testutils::{Address as _, IssuerFlags, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Env,
};

const UNITS: i128 = 10;
const PRICE: i128 = 2_500_000_000; // 250 USDC (7 decimals)

struct S<'a> {
    env: Env,
    dvp: ComplianceDvpClient<'a>,
    gate: ComplianceGateClient<'a>,
    mock: MockVerifierClient<'a>,
    security: TokenClient<'a>,
    security_admin: StellarAssetClient<'a>,
    usdc: TokenClient<'a>,
    seller: Address,
    buyer: Address,
}

fn setup<'a>() -> S<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(5_000);
    let admin = Address::generate(&env);

    // receivable token (CVM 88 style): the issuer controls who may hold it
    let issuer = Address::generate(&env);
    let sec = env.register_stellar_asset_contract_v2(issuer);
    // AUTH_REVOCABLE: the issuer can freeze a holder (classic asset flag)
    sec.issuer().set_flag(IssuerFlags::RevocableFlag);
    let security = TokenClient::new(&env, &sec.address());
    let security_admin = StellarAssetClient::new(&env, &sec.address());
    let usdc_sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let usdc = TokenClient::new(&env, &usdc_sac.address());

    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);
    security_admin.mint(&seller, &100);
    StellarAssetClient::new(&env, &usdc_sac.address()).mint(&buyer, &100_000_000_000);

    let mock_id = env.register(MockVerifier, ());
    let mock = MockVerifierClient::new(&env, &mock_id);
    mock.set_result(&true);
    let gate_id = env.register(ComplianceGate, (admin, mock_id, Address::generate(&env)));
    let gate = ComplianceGateClient::new(&env, &gate_id);
    gate.set_policy(&1, &policy(&env));
    let dvp_id = env.register(ComplianceDvp, (gate_id,));
    let dvp = ComplianceDvpClient::new(&env, &dvp_id);
    S {
        env,
        dvp,
        gate,
        mock,
        security,
        security_admin,
        usdc,
        seller,
        buyer,
    }
}

fn open(s: &S) -> u64 {
    let id = s.dvp.offer(
        &s.seller,
        &s.buyer,
        &s.security.address,
        &UNITS,
        &s.usdc.address,
        &PRICE,
        &9_000,
        &1,
    );
    s.dvp.fund(&id);
    id
}

fn proof(env: &Env) -> Proof {
    let g = gate_proof(env);
    Proof {
        a: g.a,
        b: g.b,
        c: g.c,
    }
}

fn sig(s: &S, id: u64) -> soroban_sdk::Vec<Fr> {
    let p = s.gate.policy(&1);
    signals(&s.env, &p, &s.dvp.context(&id), 2_000)
}

#[test]
fn settles_both_legs_in_one_call() {
    let s = setup();
    let id = open(&s);
    assert_eq!(s.security.balance(&s.dvp.address), UNITS);
    assert_eq!(s.usdc.balance(&s.dvp.address), PRICE);
    s.dvp.settle(&id, &proof(&s.env), &sig(&s, id));
    assert_eq!(s.dvp.get(&id).state, State::Settled);
    assert_eq!(s.security.balance(&s.buyer), UNITS);
    assert_eq!(s.usdc.balance(&s.seller), PRICE);
    assert_eq!(s.security.balance(&s.dvp.address), 0);
    assert_eq!(s.usdc.balance(&s.dvp.address), 0);
}

#[test]
fn refused_proof_moves_nothing() {
    let s = setup();
    let id = open(&s);
    s.mock.set_result(&false);
    assert!(s.dvp.try_settle(&id, &proof(&s.env), &sig(&s, id)).is_err());
    assert_eq!(s.dvp.get(&id).state, State::Funded);
    assert_eq!(s.security.balance(&s.buyer), 0);
    assert_eq!(s.usdc.balance(&s.seller), 0);
}

#[test]
fn proof_for_another_trade_is_refused() {
    let s = setup();
    let a = open(&s);
    let b = open(&s);
    assert!(s.dvp.try_settle(&a, &proof(&s.env), &sig(&s, b)).is_err());
    assert_eq!(s.dvp.get(&a).state, State::Funded);
}

#[test]
fn buyer_not_authorized_by_the_issuer_reverts_the_settlement() {
    let s = setup();
    let id = open(&s);
    // the issuer freezes the buyer: compliance proof alone is not enough
    s.security_admin.set_authorized(&s.buyer, &false);
    assert!(s.dvp.try_settle(&id, &proof(&s.env), &sig(&s, id)).is_err());
    assert_eq!(s.dvp.get(&id).state, State::Funded);
    assert_eq!(s.usdc.balance(&s.seller), 0);
    // authorized again: it settles
    s.security_admin.set_authorized(&s.buyer, &true);
    s.dvp.settle(&id, &proof(&s.env), &sig(&s, id));
    assert_eq!(s.security.balance(&s.buyer), UNITS);
}

#[test]
fn cancel_after_deadline_returns_each_leg() {
    let s = setup();
    let id = open(&s);
    let offered_only = s.dvp.offer(
        &s.seller,
        &s.buyer,
        &s.security.address,
        &UNITS,
        &s.usdc.address,
        &PRICE,
        &9_000,
        &1,
    );
    assert_eq!(s.dvp.try_cancel(&id), Err(Ok(Error::NotExpired)));
    s.env.ledger().set_timestamp(9_001);
    assert!(s.dvp.try_settle(&id, &proof(&s.env), &sig(&s, id)).is_err());
    assert_eq!(s.dvp.try_fund(&offered_only), Err(Ok(Error::Expired)));
    s.dvp.cancel(&id);
    s.dvp.cancel(&offered_only);
    assert_eq!(s.security.balance(&s.seller), 100);
    assert_eq!(s.usdc.balance(&s.buyer), 100_000_000_000);
    assert_eq!(s.dvp.try_cancel(&id), Err(Ok(Error::WrongState)));
}

#[test]
fn offer_validates_and_settle_needs_both_legs() {
    let s = setup();
    let bad = |a: i128, c: i128, d: u64| {
        s.dvp.try_offer(
            &s.seller,
            &s.buyer,
            &s.security.address,
            &a,
            &s.usdc.address,
            &c,
            &d,
            &1,
        )
    };
    assert_eq!(bad(0, PRICE, 9_000), Err(Ok(Error::InvalidAmount)));
    assert_eq!(bad(UNITS, 0, 9_000), Err(Ok(Error::InvalidAmount)));
    assert_eq!(bad(UNITS, PRICE, 5_000), Err(Ok(Error::InvalidDeadline)));
    let id = s.dvp.offer(
        &s.seller,
        &s.buyer,
        &s.security.address,
        &UNITS,
        &s.usdc.address,
        &PRICE,
        &9_000,
        &1,
    );
    assert_eq!(
        s.dvp.try_settle(&id, &proof(&s.env), &sig(&s, id)),
        Err(Ok(Error::WrongState))
    );
    s.dvp.fund(&id);
    assert_eq!(s.dvp.try_fund(&id), Err(Ok(Error::WrongState)));
}

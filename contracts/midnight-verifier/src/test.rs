//! Real Midnight proof (midnight-zk-stdlib 2.4.0, Poseidon preimage, k=6)
//! from `fixtures/midnight/poseidon`, made by `tools/midnight-export`.
extern crate std;

use std::{string::String, vec::Vec as StdVec};

use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec, U256};

use crate::{Error, MidnightVerifier, MidnightVerifierClient};

const SVK: &[u8] = include_bytes!("../../../fixtures/midnight/poseidon/vk.svk");
const PROOF: &[u8] = include_bytes!("../../../fixtures/midnight/poseidon/proof.bin");
const PI: &str = include_str!("../../../fixtures/midnight/poseidon/pi.hex");
const HINTS: &str = include_str!("../../../fixtures/midnight/poseidon/hints.hex");

fn unhex(s: &str) -> StdVec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct T {
    env: Env,
    c: MidnightVerifierClient<'static>,
    vk: BytesN<32>,
    proof: Bytes,
    hints: Vec<BytesN<96>>,
    statement: Vec<U256>,
}

fn setup() -> T {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(MidnightVerifier, (admin,));
    let c = MidnightVerifierClient::new(&env, &id);
    let vk = c.register_vk(&Bytes::from_slice(&env, SVK));
    let proof = Bytes::from_slice(&env, PROOF);
    let mut hints = Vec::new(&env);
    for l in HINTS.lines() {
        let b: [u8; 96] = unhex(l.trim()).try_into().unwrap();
        hints.push_back(BytesN::from_array(&env, &b));
    }
    let mut statement = Vec::new(&env);
    for l in PI.lines() {
        let mut be: [u8; 32] = unhex(l.trim()).try_into().unwrap();
        be.reverse();
        statement.push_back(U256::from_be_bytes(&env, &Bytes::from_array(&env, &be)));
    }
    T {
        env,
        c,
        vk,
        proof,
        hints,
        statement,
    }
}

#[test]
fn real_midnight_proof_verifies_on_soroban() {
    let t = setup();
    t.env.cost_estimate().budget().reset_unlimited();
    assert!(t.c.verify(&t.vk, &t.proof, &t.hints, &t.statement));
    let budget = t.env.cost_estimate().budget();
    std::println!(
        "midnight verify: cpu {} instructions, mem {} bytes",
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost()
    );
    assert!(
        budget.cpu_instruction_cost() < 400_000_000,
        "over the per-transaction cap"
    );
}

#[test]
fn wrong_statement_is_rejected() {
    let t = setup();
    t.env.cost_estimate().budget().reset_unlimited();
    let mut s = t.statement.clone();
    let v = s.get(0).unwrap();
    s.set(0, v.add(&U256::from_u32(&t.env, 1)));
    assert!(!t.c.verify(&t.vk, &t.proof, &t.hints, &s));
}

#[test]
fn tampered_proof_is_rejected() {
    let t = setup();
    t.env.cost_estimate().budget().reset_unlimited();
    // flip a bit inside the last scalar evaluation (before the final points)
    let mut p: StdVec<u8> = StdVec::from(PROOF);
    let i = p.len() - 2 * 48 - 10;
    p[i] ^= 1;
    assert!(!t.c.verify(
        &t.vk,
        &Bytes::from_slice(&t.env, &p),
        &t.hints,
        &t.statement
    ));
}

#[test]
fn hint_that_does_not_match_the_proof_is_rejected() {
    let t = setup();
    t.env.cost_estimate().budget().reset_unlimited();
    let mut h = t.hints.clone();
    // swap two hints: each still a valid curve point, but not the proof's
    let a = h.get(0).unwrap();
    let b = h.get(1).unwrap();
    h.set(0, b);
    h.set(1, a);
    assert!(!t.c.verify(&t.vk, &t.proof, &h, &t.statement));
    // an extra unused hint is refused too
    let mut h = t.hints.clone();
    h.push_back(t.hints.get(0).unwrap());
    assert!(!t.c.verify(&t.vk, &t.proof, &h, &t.statement));
}

#[test]
fn statement_out_of_field_and_unknown_vk_are_errors() {
    let t = setup();
    t.env.cost_estimate().budget().reset_unlimited();
    let mut s = Vec::new(&t.env);
    s.push_back(U256::from_be_bytes(
        &t.env,
        &Bytes::from_array(&t.env, &[0xffu8; 32]),
    ));
    assert_eq!(
        t.c.try_verify(&t.vk, &t.proof, &t.hints, &s),
        Err(Ok(Error::ValueOutOfField))
    );
    let unknown = BytesN::from_array(&t.env, &[7u8; 32]);
    assert_eq!(
        t.c.try_verify(&unknown, &t.proof, &t.hints, &t.statement),
        Err(Ok(Error::UnknownVk))
    );
}

#[test]
fn register_vk_requires_admin_and_a_valid_blob() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let id = env.register(MidnightVerifier, (admin,));
    let c = MidnightVerifierClient::new(&env, &id);
    assert!(c.try_register_vk(&Bytes::from_slice(&env, SVK)).is_err()); // no auth
    env.mock_all_auths();
    assert_eq!(
        c.try_register_vk(&Bytes::from_slice(&env, b"not an svk")),
        Err(Ok(Error::BadVk))
    );
    let h = c.register_vk(&Bytes::from_slice(&env, SVK));
    assert_eq!(c.vk(&h).unwrap().len() as usize, SVK.len());
    let _ = String::new();
}

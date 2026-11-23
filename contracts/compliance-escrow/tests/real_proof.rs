//! End to end with a REAL Groth16 proof of `circuits/sanctions/main.circom`
//! (fixtures/proofs/sanctions, dev trusted setup): real circom-verifier, real
//! gate, real escrow, a Stellar Asset Contract as testnet USDC.
//!
//! The proof's `context` signal must equal `escrow.context(1)` in this exact
//! setup (testutils addresses are deterministic). If the setup changes, run
//! `scripts/make-fixture-proof.sh <context printed by the failing test>`.

use ark_bls12_381::{Fq, Fq2};
use ark_serialize::CanonicalSerialize;
use circom_verifier::Groth16Verifier;
use compliance_escrow::{ComplianceEscrow, ComplianceEscrowClient, Proof, State};
use compliance_gate::{ComplianceGate, ComplianceGateClient, Policy, VerificationKey};
use core::str::FromStr;
use serde_json::Value;
use soroban_sdk::{
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
        G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE,
    },
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, Env, Vec, U256,
};

const PROOF: &str = include_str!("../../../fixtures/proofs/sanctions/proof.json");
const PUBLIC: &str = include_str!("../../../fixtures/proofs/sanctions/public.json");
const VK: &str = include_str!("../../../fixtures/proofs/sanctions/verification_key.json");

fn g1(env: &Env, v: &Value) -> G1Affine {
    let p = ark_bls12_381::G1Affine::new(
        Fq::from_str(v[0].as_str().unwrap()).unwrap(),
        Fq::from_str(v[1].as_str().unwrap()).unwrap(),
    );
    let mut buf = [0u8; G1_SERIALIZED_SIZE];
    p.serialize_uncompressed(&mut buf[..]).unwrap();
    G1Affine::from_array(env, &buf)
}

fn g2(env: &Env, v: &Value) -> G2Affine {
    let c = |i: usize, j: usize| Fq::from_str(v[i][j].as_str().unwrap()).unwrap();
    let p = ark_bls12_381::G2Affine::new(Fq2::new(c(0, 0), c(0, 1)), Fq2::new(c(1, 0), c(1, 1)));
    let mut buf = [0u8; G2_SERIALIZED_SIZE];
    p.serialize_uncompressed(&mut buf[..]).unwrap();
    G2Affine::from_array(env, &buf)
}

fn u256(env: &Env, dec: &str) -> U256 {
    let n = num_be_bytes(dec);
    U256::from_be_bytes(env, &Bytes::from_array(env, &n))
}

/// Decimal string -> 32-byte big-endian.
fn num_be_bytes(dec: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for ch in dec.bytes() {
        let mut carry = (ch - b'0') as u32;
        for b in out.iter_mut().rev() {
            let v = (*b as u32) * 10 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
    }
    out
}

struct World<'a> {
    env: Env,
    escrow: ComplianceEscrowClient<'a>,
    usdc: TokenClient<'a>,
    beneficiary: Address,
    payer: Address,
    public: Vec<Fr>,
    proof: Proof,
}

fn world<'a>() -> World<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().set_timestamp(1_795_900_100);

    let proof_json: Value = serde_json::from_str(PROOF).unwrap();
    let public_json: Value = serde_json::from_str(PUBLIC).unwrap();
    let vk_json: Value = serde_json::from_str(VK).unwrap();
    let pubs: std::vec::Vec<&str> = public_json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let admin = Address::generate(&env);
    let verifier_id = env.register(Groth16Verifier {}, (admin.clone(),));
    let gate_id = env.register(
        ComplianceGate,
        (admin.clone(), verifier_id, Address::generate(&env)),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);

    let mut ic = Vec::new(&env);
    for p in vk_json["IC"].as_array().unwrap() {
        ic.push_back(g1(&env, p));
    }
    gate.set_policy(
        &1,
        &Policy {
            sanctions_root: u256(&env, pubs[0]),
            pepper_commit: u256(&env, pubs[1]),
            policy_hash: u256(&env, pubs[2]),
            min_issued_at: 1_795_000_000,
            valid_until: 1_796_000_000,
            vk: VerificationKey {
                alpha: g1(&env, &vk_json["vk_alpha_1"]),
                beta: g2(&env, &vk_json["vk_beta_2"]),
                gamma: g2(&env, &vk_json["vk_gamma_2"]),
                delta: g2(&env, &vk_json["vk_delta_2"]),
                ic,
            },
        },
    );

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let usdc = TokenClient::new(&env, &sac.address());
    let payer = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&payer, &10_000_000_000);

    let escrow_id = env.register(ComplianceEscrow, (admin, gate_id));
    let escrow = ComplianceEscrowClient::new(&env, &escrow_id);
    let beneficiary = Address::generate(&env);

    let mut public = Vec::new(&env);
    for p in &pubs {
        public.push_back(Fr::from_u256(u256(&env, p)));
    }
    let proof = Proof {
        a: g1(&env, &proof_json["pi_a"]),
        b: g2(&env, &proof_json["pi_b"]),
        c: g1(&env, &proof_json["pi_c"]),
    };
    World {
        env,
        escrow,
        usdc,
        beneficiary,
        payer,
        public,
        proof,
    }
}

/// 32-byte big-endian (as soroban Bytes) -> decimal string.
fn be_to_dec(b: &Bytes) -> std::string::String {
    let mut n: std::vec::Vec<u8> = b.iter().collect();
    let mut digits = std::vec::Vec::new();
    while n.iter().any(|&x| x != 0) {
        let mut rem = 0u32;
        for x in n.iter_mut() {
            let cur = rem * 256 + *x as u32;
            *x = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    digits.reverse();
    std::string::String::from_utf8(digits).unwrap()
}

fn deposit(w: &World) -> u64 {
    let id = w.escrow.deposit(
        &w.payer,
        &w.beneficiary,
        &w.usdc.address,
        &1_000_000_000,
        &1_795_990_000,
        &1,
    );
    let ctx = w.escrow.context(&id);
    let expected = w.public.get(3).unwrap().to_u256();
    assert_eq!(
        ctx, expected,
        "fixture proof was made for another context; regenerate with: scripts/make-fixture-proof.sh {}",
        be_to_dec(&ctx.to_be_bytes())
    );
    id
}

#[test]
fn real_proof_releases_payment() {
    let w = world();
    let id = deposit(&w);
    w.env.cost_estimate().budget().reset_default();
    w.escrow.release(&id, &w.proof, &w.public);
    std::println!(
        "release cpu instructions: {}",
        w.env.cost_estimate().budget().cpu_instruction_cost()
    );
    assert_eq!(w.usdc.balance(&w.beneficiary), 1_000_000_000);
    assert_eq!(w.escrow.get(&id).state, State::Released);
}

#[test]
fn tampered_proof_is_rejected_and_funds_stay_locked() {
    let w = world();
    let id = deposit(&w);
    // Swap A and C: valid curve points, wrong proof.
    let bad = Proof {
        a: w.proof.c.clone(),
        b: w.proof.b.clone(),
        c: w.proof.a.clone(),
    };
    assert!(w.escrow.try_release(&id, &bad, &w.public).is_err());
    assert_eq!(w.escrow.get(&id).state, State::Funded);
    assert_eq!(w.usdc.balance(&w.escrow.address), 1_000_000_000);
    assert_eq!(w.usdc.balance(&w.beneficiary), 0);
}

#[test]
fn proof_cannot_be_replayed_on_another_escrow() {
    let w = world();
    let id = deposit(&w);
    let other = w.escrow.deposit(
        &w.payer,
        &w.beneficiary,
        &w.usdc.address,
        &1_000_000_000,
        &1_795_990_000,
        &1,
    );
    assert!(w.escrow.try_release(&other, &w.proof, &w.public).is_err());
    w.escrow.release(&id, &w.proof, &w.public);
    assert_eq!(w.escrow.get(&other).state, State::Funded);
}

//! Test helpers shared with dependent crates (feature `testutils`).
extern crate std;

use crate::*;
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec, U256};

// Generator points of BLS12-381 (uncompressed, big-endian). Any valid points
// work here: the mock verifier below decides the outcome.
pub const G1_GEN: [u8; 96] = hex96(
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);
pub const G2_GEN: [u8; 192] = hex192(
    "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
);
const fn hv(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}
const fn hex96(s: &str) -> [u8; 96] {
    let b = s.as_bytes();
    let mut o = [0u8; 96];
    let mut i = 0;
    while i < 96 {
        o[i] = hv(b[2 * i]) * 16 + hv(b[2 * i + 1]);
        i += 1;
    }
    o
}
const fn hex192(s: &str) -> [u8; 192] {
    let b = s.as_bytes();
    let mut o = [0u8; 192];
    let mut i = 0;
    while i < 192 {
        o[i] = hv(b[2 * i]) * 16 + hv(b[2 * i + 1]);
        i += 1;
    }
    o
}

/// Stand-in for circom-verifier: returns whatever `set_result` stored.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn set_result(env: Env, ok: bool) {
        env.storage().instance().set(&0u32, &ok);
    }
    pub fn verify_proof(
        env: Env,
        _vk: VerificationKey,
        _proof: Proof,
        _pub_signals: Vec<Fr>,
    ) -> bool {
        env.storage().instance().get(&0u32).unwrap_or(false)
    }
}

/// Stand-in for midnight-verifier.
#[contract]
pub struct MockMidnight;

#[contractimpl]
impl MockMidnight {
    pub fn set_result(env: Env, ok: bool) {
        env.storage().instance().set(&0u32, &ok);
    }
    pub fn verify(
        env: Env,
        _vk_hash: BytesN<32>,
        _proof: Bytes,
        _hints: Vec<BytesN<96>>,
        _statement: Vec<U256>,
    ) -> bool {
        env.storage().instance().get(&0u32).unwrap_or(false)
    }
}

/// Midnight policy with statement `[binding, policy_hash, context]`.
pub fn midnight_policy(env: &Env) -> MidnightPolicy {
    let mut pins = Vec::new(env);
    pins.push_back(Pin {
        index: 1,
        value: u(env, 0xA4),
    });
    MidnightPolicy {
        vk_hash: BytesN::from_array(env, &[9u8; 32]),
        statement_len: 3,
        pins,
        context_index: 2,
        valid_until: 10_000,
    }
}

pub fn g1(env: &Env) -> G1Affine {
    G1Affine::from_array(env, &G1_GEN)
}
pub fn g2(env: &Env) -> G2Affine {
    G2Affine::from_array(env, &G2_GEN)
}
pub fn proof(env: &Env) -> Proof {
    Proof {
        a: g1(env),
        b: g2(env),
        c: g1(env),
    }
}
pub fn u(env: &Env, v: u128) -> U256 {
    U256::from_u128(env, v)
}
pub fn policy(env: &Env) -> Policy {
    let mut ic = Vec::new(env);
    for _ in 0..(NUM_SIGNALS + 1) {
        ic.push_back(g1(env));
    }
    Policy {
        policy_hash: u(env, 0xA4),
        sanctions_root: u(env, 0x25FA),
        pepper_commit: u(env, 0xBEEF),
        min_issued_at: 1_000,
        valid_until: 10_000,
        vk: VerificationKey {
            alpha: g1(env),
            beta: g2(env),
            gamma: g2(env),
            delta: g2(env),
            ic,
        },
    }
}
pub fn signals(env: &Env, p: &Policy, context: &U256, issued_at: u128) -> Vec<Fr> {
    let mut v = Vec::new(env);
    v.push_back(Fr::from_u256(p.sanctions_root.clone()));
    v.push_back(Fr::from_u256(p.pepper_commit.clone()));
    v.push_back(Fr::from_u256(p.policy_hash.clone()));
    v.push_back(Fr::from_u256(context.clone()));
    v.push_back(Fr::from_u256(u(env, issued_at)));
    v
}

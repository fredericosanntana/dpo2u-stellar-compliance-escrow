//! `midnight_verifier_core::Backend` over the Soroban BLS12-381 host
//! functions.
//!
//! Soroban only takes uncompressed G1 points and has no base-field
//! arithmetic, so a point read from the (compressed) Midnight proof is
//! matched against a caller-supplied uncompressed hint: same x, and the sign
//! flag agrees with y. The host then checks the hint is on the curve and in
//! the subgroup, so a hint cannot change what the proof says.

use core::cell::RefCell;

use midnight_verifier_core::Backend;
use soroban_sdk::{
    crypto::bls12_381::{Bls12381Fr as Fr, Bls12381G1Affine as G1, Bls12381G2Affine as G2},
    Bytes, BytesN, Env, Vec, U256,
};

/// r, big-endian.
const R_MODULUS: [u8; 32] =
    hex32("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
/// 2^256 mod r, big-endian.
const R256: [u8; 32] = hex32("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe");
/// (p - 1) / 2, big-endian: y is "lexicographically largest" iff y > HALF_P.
const HALF_P: [u8; 48] = {
    let a = hex32("0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12");
    let b = hex32("0f55ffff58a9ffffdcff7fffffffd55500000000000000000000000000000000");
    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 32 {
        out[i] = a[i];
        i += 1;
    }
    while i < 48 {
        out[i] = b[i - 32];
        i += 1;
    }
    out
};
const G1_GENERATOR: [u8; 96] = {
    let x = hex48(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    );
    let y = hex48(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
    );
    let mut out = [0u8; 96];
    let mut i = 0;
    while i < 48 {
        out[i] = x[i];
        out[48 + i] = y[i];
        i += 1;
    }
    out
};

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    }
}
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn hex48(s: &str) -> [u8; 48] {
    let b = s.as_bytes();
    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 48 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

pub struct Soroban<'a> {
    env: &'a Env,
    modulus: U256,
    zero: Fr,
    one: Fr,
    r256: Fr,
    hints: Vec<BytesN<96>>,
    next_hint: RefCell<u32>,
}

impl<'a> Soroban<'a> {
    pub fn new(env: &'a Env, hints: Vec<BytesN<96>>) -> Self {
        let u = |be: &[u8; 32]| U256::from_be_bytes(env, &Bytes::from_array(env, be));
        Soroban {
            env,
            modulus: u(&R_MODULUS),
            zero: Fr::from_u256(U256::from_u32(env, 0)),
            one: Fr::from_u256(U256::from_u32(env, 1)),
            r256: Fr::from_u256(u(&R256)),
            hints,
            next_hint: RefCell::new(0),
        }
    }

    pub fn all_hints_used(&self) -> bool {
        *self.next_hint.borrow() == self.hints.len()
    }

    fn le_to_u256(&self, le: &[u8]) -> U256 {
        let mut be = [0u8; 32];
        for (i, b) in le.iter().enumerate() {
            be[31 - i] = *b;
        }
        U256::from_be_bytes(self.env, &Bytes::from_array(self.env, &be))
    }

    fn bls(&self) -> soroban_sdk::crypto::bls12_381::Bls12_381 {
        self.env.crypto().bls12_381()
    }
}

impl Backend for Soroban<'_> {
    type Fr = Fr;
    type G1 = G1;

    fn zero(&self) -> Fr {
        self.zero.clone()
    }
    fn one(&self) -> Fr {
        self.one.clone()
    }
    fn from_u64(&self, v: u64) -> Fr {
        Fr::from_u256(U256::from_u128(self.env, v as u128))
    }
    fn add(&self, a: &Fr, b: &Fr) -> Fr {
        self.bls().fr_add(a, b)
    }
    fn sub(&self, a: &Fr, b: &Fr) -> Fr {
        self.bls().fr_sub(a, b)
    }
    fn mul(&self, a: &Fr, b: &Fr) -> Fr {
        self.bls().fr_mul(a, b)
    }
    fn inv(&self, a: &Fr) -> Option<Fr> {
        if a.as_u256() == self.zero.as_u256() {
            None
        } else {
            Some(self.bls().fr_inv(a))
        }
    }
    fn pow(&self, a: &Fr, e: u64) -> Fr {
        self.bls().fr_pow(a, e)
    }
    fn from_le_canonical(&self, b: &[u8; 32]) -> Option<Fr> {
        let u = self.le_to_u256(b);
        if u >= self.modulus {
            None
        } else {
            Some(Fr::from_u256(u))
        }
    }
    fn from_uniform(&self, b: &[u8; 64]) -> Fr {
        let lo = Fr::from_u256(self.le_to_u256(&b[..32]));
        let hi = Fr::from_u256(self.le_to_u256(&b[32..]));
        self.add(&lo, &self.mul(&hi, &self.r256))
    }

    fn g1_decompress(&self, c: &[u8; 48]) -> Option<G1> {
        let flags = c[0] & 0xe0;
        if flags & 0x80 == 0 {
            return None; // not a compressed encoding
        }
        if flags & 0x40 != 0 {
            // identity: no sort flag, all other bits zero; needs no hint
            if flags & 0x20 != 0 || c[0] & 0x1f != 0 || c[1..].iter().any(|&b| b != 0) {
                return None;
            }
            let mut id = [0u8; 96];
            id[0] = 0x40;
            return Some(G1::from_array(self.env, &id));
        }
        let mut i = self.next_hint.borrow_mut();
        let hint = self.hints.get(*i)?.to_array();
        *i += 1;
        if hint[0] & 0xe0 != 0 || hint[0] != c[0] & 0x1f || hint[1..48] != c[1..48] {
            return None;
        }
        let y_is_largest = hint[48..96] > HALF_P[..];
        if y_is_largest != (flags & 0x20 != 0) {
            return None;
        }
        let p = G1::from_array(self.env, &hint);
        // traps (fails the transaction) if the hint is not on the curve
        if !self.bls().g1_is_in_subgroup(&p) {
            return None;
        }
        Some(p)
    }
    fn g1_uncompressed(&self, u: &[u8; 96]) -> Option<G1> {
        Some(G1::from_array(self.env, u))
    }
    fn g1_generator(&self) -> G1 {
        G1::from_array(self.env, &G1_GENERATOR)
    }
    fn g1_is_identity(&self, p: &G1) -> bool {
        p.to_array()[0] & 0x40 != 0
    }
    fn msm(&self, bases: &[G1], scalars: &[Fr]) -> G1 {
        let mut vp = Vec::new(self.env);
        let mut vs = Vec::new(self.env);
        for (b, s) in bases.iter().zip(scalars) {
            vp.push_back(b.clone());
            vs.push_back(s.clone());
        }
        self.bls().g1_msm(vp, vs)
    }
    fn pairing_check(&self, a1: &G1, b1: &[u8; 192], a2: &G1, b2: &[u8; 192]) -> bool {
        let mut vp1 = Vec::new(self.env);
        vp1.push_back(a1.clone());
        vp1.push_back(a2.clone());
        let mut vp2 = Vec::new(self.env);
        vp2.push_back(G2::from_array(self.env, b1));
        vp2.push_back(G2::from_array(self.env, b2));
        self.bls().pairing_check(vp1, vp2)
    }
}

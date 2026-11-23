#![no_std]
//! DPO2U — `compliance-gate`.
//!
//! The gate is the only place where the compliance policy lives on Stellar.
//! For each `policy_id` the admin pins:
//! - `sanctions_root`: root of the indexed Merkle tree of the sanctions
//!   snapshot (entries are `H(pepper, sha256(id))`, same scheme as the
//!   Midnight TravelRuleGate v12, so no reversible identifier hash is public);
//! - `pepper_commit`: the provider-signed commitment to that snapshot's pepper;
//! - `policy_hash`: hash of the rule pack (LGPD + Travel Rule + PSAV/CVM);
//! - `min_issued_at` / `valid_until`: freshness window of the snapshot;
//! - `vk`: Groth16 verifier key of the Circom non-membership circuit.
//!
//! A proof is accepted only if its public signals match the pinned values
//! AND the escrow's `context` (so a proof cannot be replayed on another
//! escrow), and the Groth16 verifier accepts it.
//!
//! Public signal layout of the Circom lane (fixed; see docs/circuit.md):
//! `[sanctions_root, pepper_commit, policy_hash, context, issued_at]`.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
    },
    Address, Env, Vec, U256,
};

pub const SIG_ROOT: u32 = 0;
pub const SIG_PEPPER_COMMIT: u32 = 1;
pub const SIG_POLICY_HASH: u32 = 2;
pub const SIG_CONTEXT: u32 = 3;
pub const SIG_ISSUED_AT: u32 = 4;
pub const NUM_SIGNALS: u32 = 5;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    UnknownPolicy = 2,
    BadSignalCount = 3,
    RootMismatch = 4,
    PepperCommitMismatch = 5,
    PolicyHashMismatch = 6,
    ContextMismatch = 7,
    StaleSnapshot = 8,
    PolicyExpired = 9,
    InvalidProof = 10,
    ValueOutOfField = 11,
    MidnightLaneNotImplemented = 12,
}

#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[derive(Clone)]
#[contracttype]
pub struct Policy {
    pub policy_hash: U256,
    pub sanctions_root: U256,
    pub pepper_commit: U256,
    pub min_issued_at: u64,
    pub valid_until: u64,
    pub vk: VerificationKey,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    CircomVerifier,
    MidnightVerifier,
    Policy(u32),
}

/// Interface of `circom-verifier` (Caatinga zk-starter verifier).
#[contractclient(name = "CircomVerifierClient")]
pub trait CircomVerifierInterface {
    fn verify_proof(env: Env, vk: VerificationKey, proof: Proof, pub_signals: Vec<Fr>) -> bool;
}

#[contractevent(topics = ["policy_set"])]
pub struct PolicySet {
    #[topic]
    pub policy_id: u32,
    pub policy_hash: U256,
    pub sanctions_root: U256,
    pub valid_until: u64,
}

#[contractevent(topics = ["verdict"])]
pub struct Verdict {
    #[topic]
    pub policy_id: u32,
    pub context: U256,
    pub pass: bool,
}

#[contract]
pub struct ComplianceGate;

/// Largest value accepted as a public signal: 2^248 - 1 (always below the
/// BLS12-381 scalar modulus, so no silent reduction can happen).
fn fits_field(v: &U256) -> bool {
    v.to_be_bytes().get(0) == Some(0)
}

#[contractimpl]
impl ComplianceGate {
    pub fn __constructor(
        env: Env,
        admin: Address,
        circom_verifier: Address,
        midnight_verifier: Address,
    ) {
        let s = env.storage().instance();
        s.set(&DataKey::Admin, &admin);
        s.set(&DataKey::CircomVerifier, &circom_verifier);
        s.set(&DataKey::MidnightVerifier, &midnight_verifier);
    }

    pub fn admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    pub fn circom_verifier(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::CircomVerifier)
            .ok_or(Error::NotInitialized)
    }

    pub fn midnight_verifier(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::MidnightVerifier)
            .ok_or(Error::NotInitialized)
    }

    /// Pins (or rotates) a policy. Admin only. Every change is an event.
    pub fn set_policy(env: Env, policy_id: u32, policy: Policy) -> Result<(), Error> {
        Self::admin(env.clone())?.require_auth();
        if !fits_field(&policy.policy_hash)
            || !fits_field(&policy.sanctions_root)
            || !fits_field(&policy.pepper_commit)
        {
            return Err(Error::ValueOutOfField);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);
        PolicySet {
            policy_id,
            policy_hash: policy.policy_hash.clone(),
            sanctions_root: policy.sanctions_root.clone(),
            valid_until: policy.valid_until,
        }
        .publish(&env);
        Ok(())
    }

    pub fn policy(env: Env, policy_id: u32) -> Result<Policy, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(Error::UnknownPolicy)
    }

    /// Circom lane: accepts only if every pinned value and the escrow context
    /// match the public signals, the snapshot is fresh, and the proof verifies.
    pub fn check_circom(
        env: Env,
        policy_id: u32,
        context: U256,
        proof: Proof,
        pub_signals: Vec<Fr>,
    ) -> Result<bool, Error> {
        let p = Self::policy(env.clone(), policy_id)?;
        if pub_signals.len() != NUM_SIGNALS {
            return Err(Error::BadSignalCount);
        }
        let sig = |i: u32| pub_signals.get(i).unwrap().to_u256();
        if sig(SIG_ROOT) != p.sanctions_root {
            return Err(Error::RootMismatch);
        }
        if sig(SIG_PEPPER_COMMIT) != p.pepper_commit {
            return Err(Error::PepperCommitMismatch);
        }
        if sig(SIG_POLICY_HASH) != p.policy_hash {
            return Err(Error::PolicyHashMismatch);
        }
        if sig(SIG_CONTEXT) != context {
            return Err(Error::ContextMismatch);
        }
        let issued_at = sig(SIG_ISSUED_AT);
        if issued_at < U256::from_u128(&env, p.min_issued_at as u128) {
            return Err(Error::StaleSnapshot);
        }
        if env.ledger().timestamp() > p.valid_until {
            return Err(Error::PolicyExpired);
        }
        let verifier = CircomVerifierClient::new(&env, &Self::circom_verifier(env.clone())?);
        if !verifier.verify_proof(&p.vk, &proof, &pub_signals) {
            return Err(Error::InvalidProof);
        }
        Verdict {
            policy_id,
            context,
            pass: true,
        }
        .publish(&env);
        Ok(true)
    }

    /// Midnight lane (PRD phase 3): the native Midnight proof of the
    /// TravelRuleGate. Not wired yet.
    pub fn check_midnight(_env: Env, _policy_id: u32, _context: U256) -> Result<bool, Error> {
        Err(Error::MidnightLaneNotImplemented)
    }
}

#[cfg(any(test, feature = "testutils"))]
pub mod testutils;

#[cfg(test)]
mod test;

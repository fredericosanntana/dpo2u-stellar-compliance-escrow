#![no_std]
//! DPO2U — `midnight-verifier`.
//!
//! Verifies, inside Soroban, a proof produced by Midnight's proof system
//! (`midnight-proofs` 0.8.2 via `midnight-zk-stdlib` 2.4.0, the ledger's
//! stack: Plonk + KZG over BLS12-381, Blake2b transcript) against a
//! registered verifying key and a statement (the public inputs as
//! BLS12-381 scalars).
//!
//! The algorithm lives in `crates/midnight-verifier-core` and is checked
//! against the official verifier by `tools/midnight-export`. Verifying keys
//! are registered as SVK blobs (the flattened VK plus its opening plan) and
//! addressed by their sha256.
//!
//! Trust model: this proves the statement satisfies the circuit behind the
//! pinned VK. It does NOT prove that the proof was accepted on the Midnight
//! ledger (that needs a light client); the relayer only transports.

extern crate alloc;

mod backend;

use alloc::vec;
use midnight_verifier_core::{Error as CoreError, Vk};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Bytes, BytesN,
    Env, Vec, U256,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AdminNotSet = 1,
    /// The SVK blob does not decode.
    BadVk = 2,
    UnknownVk = 3,
    /// A statement value is not a canonical scalar (`>= r`).
    ValueOutOfField = 4,
    /// The VK is valid but uses a shape this verifier does not support.
    UnsupportedVk = 5,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    Vk(BytesN<32>),
}

#[contractevent(topics = ["vk_registered"])]
pub struct VkRegistered {
    #[topic]
    pub vk_hash: BytesN<32>,
    pub k: u32,
}

#[contract]
pub struct MidnightVerifier;

fn to_vec(b: &Bytes) -> alloc::vec::Vec<u8> {
    let mut v = vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut v);
    v
}

#[contractimpl]
impl MidnightVerifier {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::AdminNotSet)
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::admin(env.clone())?.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    /// Registers an SVK blob (from `tools/midnight-export`) and returns its
    /// sha256, the id the gate pins.
    pub fn register_vk(env: Env, svk: Bytes) -> Result<BytesN<32>, Error> {
        Self::admin(env.clone())?.require_auth();
        let vk = Vk::decode(&to_vec(&svk)).map_err(|_| Error::BadVk)?;
        let hash: BytesN<32> = env.crypto().sha256(&svk).into();
        env.storage()
            .persistent()
            .set(&DataKey::Vk(hash.clone()), &svk);
        VkRegistered {
            vk_hash: hash.clone(),
            k: vk.k,
        }
        .publish(&env);
        Ok(hash)
    }

    pub fn vk(env: Env, vk_hash: BytesN<32>) -> Option<Bytes> {
        env.storage().persistent().get(&DataKey::Vk(vk_hash))
    }

    /// Verifies `proof` (midnight-proofs bytes, compressed points) against
    /// `statement`. `hints` are the uncompressed forms of the non-identity
    /// points of the proof, in reading order. Returns `false` for any proof
    /// that does not verify (bad encoding, wrong hint, failed pairing).
    pub fn verify(
        env: Env,
        vk_hash: BytesN<32>,
        proof: Bytes,
        hints: Vec<BytesN<96>>,
        statement: Vec<U256>,
    ) -> Result<bool, Error> {
        let svk: Bytes = env
            .storage()
            .persistent()
            .get(&DataKey::Vk(vk_hash))
            .ok_or(Error::UnknownVk)?;
        let vk = Vk::decode(&to_vec(&svk)).map_err(|_| Error::BadVk)?;
        let mut pi = alloc::vec::Vec::with_capacity(statement.len() as usize);
        for v in statement.iter() {
            let be = v.to_be_bytes();
            let mut le = [0u8; 32];
            be.copy_into_slice(&mut le);
            le.reverse();
            pi.push(le);
        }
        let b = backend::Soroban::new(&env, hints);
        match midnight_verifier_core::verify(&b, &vk, &pi, &to_vec(&proof)) {
            Ok(()) => Ok(b.all_hints_used()),
            Err(CoreError::InvalidScalar) if pi.iter().any(|le| !b_canonical(&b, le)) => {
                Err(Error::ValueOutOfField)
            }
            Err(CoreError::Decode) => Err(Error::BadVk),
            Err(CoreError::Unsupported) => Err(Error::UnsupportedVk),
            Err(_) => Ok(false),
        }
    }
}

fn b_canonical(b: &backend::Soroban<'_>, le: &[u8; 32]) -> bool {
    use midnight_verifier_core::Backend;
    b.from_le_canonical(le).is_some()
}

#[cfg(test)]
mod test;

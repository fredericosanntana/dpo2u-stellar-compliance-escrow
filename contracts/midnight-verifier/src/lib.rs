#![no_std]
//! DPO2U — `midnight-verifier`.
//!
//! Target (PRD phase 2): verify a proof produced by Midnight's proof system
//! (`midnight-proofs`, Plonk with KZG commitments over BLS12-381, Blake2b
//! transcript) against a pinned verifier key and a statement (the public
//! inputs as BLS12-381 scalars). The circuit-specific part (gate evaluation)
//! will be generated from the verifier key by `tools/midnight-vk-codegen`.
//!
//! Feasibility, measured 2026-11-23 with the soroban-sdk 27.0.6 budget:
//! G1 MSM of 44 points ~67.2M instructions, 2-pair pairing check ~24.1M,
//! against a 400M per-transaction cap.
//!
//! HONEST STATE: phase 0 ships the interface only. `verify` refuses every
//! proof with `NotImplemented` so nothing downstream can mistake the stub for
//! a working verifier.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec, U256,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AdminNotSet = 1,
    NotImplemented = 2,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
}

#[contract]
pub struct MidnightVerifier;

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

    /// Replaces the contract WASM (new generated verifier) keeping the ID.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::admin(env.clone())?.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    /// sha256 of the Midnight verifier key this build was generated for.
    /// All zeroes until phase 2 generates a real one.
    pub fn vk_hash(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &[0u8; 32])
    }

    /// Verifies `proof` (midnight-proofs bytes) against `statement`.
    pub fn verify(_env: Env, _proof: Bytes, _statement: Vec<U256>) -> Result<bool, Error> {
        Err(Error::NotImplemented)
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn stub_refuses_every_proof() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let id = env.register(MidnightVerifier, (admin.clone(),));
        let c = MidnightVerifierClient::new(&env, &id);
        assert_eq!(c.admin(), admin);
        let r = c.try_verify(&Bytes::new(&env), &Vec::new(&env));
        assert_eq!(r, Err(Ok(Error::NotImplemented)));
    }
}

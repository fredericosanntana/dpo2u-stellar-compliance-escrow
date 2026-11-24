#![no_std]
//! DPO2U — `compliance-escrow`.
//!
//! A payer locks a Stellar asset (any SAC: testnet USDC, or a tokenized
//! security) for a beneficiary. The funds move only in two ways:
//! - `release`: the compliance gate accepts a proof bound to THIS escrow
//!   (its `context`), then the beneficiary is paid;
//! - `refund`: after the deadline (or a proven rejection) the payer is paid back.
//!
//! No personal data is stored or emitted: the beneficiary is a Stellar
//! address and the compliance evidence is a proof (see docs/compliance-and-risk.md).
//!
//! Partial states: every call is one Soroban transaction. If anything fails
//! (gate refuses, token transfer traps, budget exceeded) the whole call
//! reverts and the escrow stays `Funded`. State is written before any token
//! transfer.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
    },
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Vec, U256,
};

const CONTEXT_DOMAIN: &[u8] = b"dpo2u.compliance-escrow.context/1";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    UnknownEscrow = 2,
    InvalidAmount = 3,
    InvalidDeadline = 4,
    NotFunded = 5,
    Expired = 6,
    NotRefundable = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[contracttype]
pub enum State {
    Funded = 0,
    Released = 1,
    /// Reached only through the Midnight lane (a proven FAIL verdict), PRD phase 3.
    Rejected = 2,
    Refunded = 3,
}

#[derive(Clone)]
#[contracttype]
pub struct Escrow {
    pub payer: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub deadline: u64,
    pub policy_id: u32,
    pub state: State,
}

/// Same shape as compliance-gate's `Proof`.
#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[contractclient(name = "GateClient")]
pub trait GateInterface {
    fn check_circom(
        env: Env,
        policy_id: u32,
        context: U256,
        proof: Proof,
        pub_signals: Vec<Fr>,
    ) -> bool;
    fn check_midnight(
        env: Env,
        policy_id: u32,
        context: U256,
        proof: Bytes,
        hints: Vec<BytesN<96>>,
        statement: Vec<U256>,
    ) -> bool;
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Admin,
    Gate,
    NextId,
    Escrow(u64),
}

#[contractevent(topics = ["funded"])]
pub struct Funded {
    #[topic]
    pub id: u64,
    pub token: Address,
    pub amount: i128,
    pub deadline: u64,
    pub policy_id: u32,
}

#[contractevent(topics = ["released"])]
pub struct Released {
    #[topic]
    pub id: u64,
}

#[contractevent(topics = ["refunded"])]
pub struct Refunded {
    #[topic]
    pub id: u64,
}

#[contract]
pub struct ComplianceEscrow;

#[contractimpl]
impl ComplianceEscrow {
    pub fn __constructor(env: Env, admin: Address, gate: Address) {
        let s = env.storage().instance();
        s.set(&DataKey::Admin, &admin);
        s.set(&DataKey::Gate, &gate);
        s.set(&DataKey::NextId, &1u64);
    }

    pub fn admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    pub fn gate(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Gate)
            .ok_or(Error::NotInitialized)
    }

    /// Locks `amount` of `token` from `payer`. Returns the escrow id.
    pub fn deposit(
        env: Env,
        payer: Address,
        beneficiary: Address,
        token: Address,
        amount: i128,
        deadline: u64,
        policy_id: u32,
    ) -> Result<u64, Error> {
        payer.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidDeadline);
        }
        let s = env.storage().instance();
        let id: u64 = s.get(&DataKey::NextId).ok_or(Error::NotInitialized)?;
        s.set(&DataKey::NextId, &(id + 1));
        let e = Escrow {
            payer: payer.clone(),
            beneficiary,
            token: token.clone(),
            amount,
            deadline,
            policy_id,
            state: State::Funded,
        };
        env.storage().persistent().set(&DataKey::Escrow(id), &e);
        token::Client::new(&env, &token).transfer(&payer, env.current_contract_address(), &amount);
        Funded {
            id,
            token,
            amount,
            deadline,
            policy_id,
        }
        .publish(&env);
        Ok(id)
    }

    pub fn get(env: Env, id: u64) -> Result<Escrow, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(id))
            .ok_or(Error::UnknownEscrow)
    }

    /// The value the proof must carry as its `context` public signal:
    /// sha256(domain | escrow contract | id | beneficiary | token | amount |
    /// deadline | policy_id) with the first byte zeroed, so it fits the
    /// BLS12-381 scalar field. Binds a proof to exactly one escrow.
    pub fn context(env: Env, id: u64) -> Result<U256, Error> {
        let e = Self::get(env.clone(), id)?;
        let mut b = Bytes::from_slice(&env, CONTEXT_DOMAIN);
        b.append(&env.current_contract_address().to_xdr(&env));
        b.extend_from_array(&id.to_be_bytes());
        b.append(&e.beneficiary.to_xdr(&env));
        b.append(&e.token.to_xdr(&env));
        b.extend_from_array(&e.amount.to_be_bytes());
        b.extend_from_array(&e.deadline.to_be_bytes());
        b.extend_from_array(&e.policy_id.to_be_bytes());
        let mut h = env.crypto().sha256(&b).to_array();
        h[0] = 0;
        Ok(U256::from_be_bytes(&env, &Bytes::from_array(&env, &h)))
    }

    /// Pays the beneficiary if the gate accepts the proof for this escrow.
    /// Anyone may submit the proof (the relayer cannot forge one).
    pub fn release(env: Env, id: u64, proof: Proof, pub_signals: Vec<Fr>) -> Result<(), Error> {
        let (e, context) = Self::releasable(&env, id)?;
        // Traps (reverting everything) if the gate refuses.
        GateClient::new(&env, &Self::gate(env.clone())?).check_circom(
            &e.policy_id,
            &context,
            &proof,
            &pub_signals,
        );
        Self::pay(&env, id, e);
        Ok(())
    }

    /// Same as `release`, with a native Midnight proof (Compact circuit)
    /// through the gate's Midnight lane. `hints` are the uncompressed forms
    /// of the proof's G1 points (see docs/midnight-verifier.md).
    pub fn release_midnight(
        env: Env,
        id: u64,
        proof: Bytes,
        hints: Vec<BytesN<96>>,
        statement: Vec<U256>,
    ) -> Result<(), Error> {
        let (e, context) = Self::releasable(&env, id)?;
        GateClient::new(&env, &Self::gate(env.clone())?).check_midnight(
            &e.policy_id,
            &context,
            &proof,
            &hints,
            &statement,
        );
        Self::pay(&env, id, e);
        Ok(())
    }

    /// Returns the funds to the payer after the deadline, or after a proven rejection.
    pub fn refund(env: Env, id: u64) -> Result<(), Error> {
        let mut e = Self::get(env.clone(), id)?;
        let refundable = match e.state {
            State::Rejected => true,
            State::Funded => env.ledger().timestamp() > e.deadline,
            _ => false,
        };
        if !refundable {
            return Err(Error::NotRefundable);
        }
        e.state = State::Refunded;
        env.storage().persistent().set(&DataKey::Escrow(id), &e);
        token::Client::new(&env, &e.token).transfer(
            &env.current_contract_address(),
            &e.payer,
            &e.amount,
        );
        Refunded { id }.publish(&env);
        Ok(())
    }
}

impl ComplianceEscrow {
    fn releasable(env: &Env, id: u64) -> Result<(Escrow, U256), Error> {
        let e = Self::get(env.clone(), id)?;
        if e.state != State::Funded {
            return Err(Error::NotFunded);
        }
        if env.ledger().timestamp() > e.deadline {
            return Err(Error::Expired);
        }
        let context = Self::context(env.clone(), id)?;
        Ok((e, context))
    }

    fn pay(env: &Env, id: u64, mut e: Escrow) {
        e.state = State::Released;
        env.storage().persistent().set(&DataKey::Escrow(id), &e);
        token::Client::new(env, &e.token).transfer(
            &env.current_contract_address(),
            &e.beneficiary,
            &e.amount,
        );
        Released { id }.publish(env);
    }
}

#[cfg(test)]
mod test;

#![no_std]
//! DPO2U — `compliance-dvp`: delivery versus payment for a tokenized security.
//!
//! A seller (issuer or holder of a security token, e.g. a receivable token in
//! the style of CVM Resolution 88) offers `asset_amount` of `asset` to one
//! buyer for `cash_amount` of `cash` (testnet USDC). Both legs are locked in
//! this contract and move in ONE call:
//! - `settle` / `settle_midnight`: the compliance gate accepts a proof bound
//!   to THIS trade (`context`), then the security goes to the buyer and the
//!   cash to the seller, or nothing moves;
//! - `cancel`: after the deadline, each side gets its own leg back.
//!
//! The security token keeps its own controls: a SAC whose issuer requires
//! authorization refuses a buyer it has not authorized (or has frozen), and
//! the whole settlement reverts. The gate adds what the token cannot see:
//! sanctions screening, Travel Rule and the rule pack, proven without
//! personal data on chain.

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    crypto::bls12_381::{
        Bls12381Fr as Fr, Bls12381G1Affine as G1Affine, Bls12381G2Affine as G2Affine,
    },
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Vec, U256,
};

const CONTEXT_DOMAIN: &[u8] = b"dpo2u.compliance-dvp.context/1";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    UnknownTrade = 2,
    InvalidAmount = 3,
    InvalidDeadline = 4,
    WrongState = 5,
    Expired = 6,
    NotExpired = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[contracttype]
pub enum State {
    /// The seller locked the security; waiting for the buyer's cash.
    Offered = 0,
    /// Both legs locked; waiting for a compliance proof.
    Funded = 1,
    Settled = 2,
    Cancelled = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Trade {
    pub seller: Address,
    pub buyer: Address,
    pub asset: Address,
    pub asset_amount: i128,
    pub cash: Address,
    pub cash_amount: i128,
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
    Gate,
    NextId,
    Trade(u64),
}

#[contractevent(topics = ["offered"])]
pub struct Offered {
    #[topic]
    pub id: u64,
    pub asset: Address,
    pub asset_amount: i128,
    pub cash: Address,
    pub cash_amount: i128,
    pub deadline: u64,
    pub policy_id: u32,
}

#[contractevent(topics = ["funded"])]
pub struct Funded {
    #[topic]
    pub id: u64,
}

#[contractevent(topics = ["settled"])]
pub struct Settled {
    #[topic]
    pub id: u64,
}

#[contractevent(topics = ["cancelled"])]
pub struct Cancelled {
    #[topic]
    pub id: u64,
}

#[contract]
pub struct ComplianceDvp;

#[contractimpl]
impl ComplianceDvp {
    pub fn __constructor(env: Env, gate: Address) {
        let s = env.storage().instance();
        s.set(&DataKey::Gate, &gate);
        s.set(&DataKey::NextId, &1u64);
    }

    pub fn gate(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Gate)
            .ok_or(Error::NotInitialized)
    }

    pub fn get(env: Env, id: u64) -> Result<Trade, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Trade(id))
            .ok_or(Error::UnknownTrade)
    }

    /// The seller locks the security and names the buyer and the price.
    #[allow(clippy::too_many_arguments)]
    pub fn offer(
        env: Env,
        seller: Address,
        buyer: Address,
        asset: Address,
        asset_amount: i128,
        cash: Address,
        cash_amount: i128,
        deadline: u64,
        policy_id: u32,
    ) -> Result<u64, Error> {
        seller.require_auth();
        if asset_amount <= 0 || cash_amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidDeadline);
        }
        let s = env.storage().instance();
        let id: u64 = s.get(&DataKey::NextId).ok_or(Error::NotInitialized)?;
        s.set(&DataKey::NextId, &(id + 1));
        let t = Trade {
            seller: seller.clone(),
            buyer,
            asset: asset.clone(),
            asset_amount,
            cash: cash.clone(),
            cash_amount,
            deadline,
            policy_id,
            state: State::Offered,
        };
        env.storage().persistent().set(&DataKey::Trade(id), &t);
        token::Client::new(&env, &asset).transfer(
            &seller,
            env.current_contract_address(),
            &asset_amount,
        );
        Offered {
            id,
            asset,
            asset_amount,
            cash,
            cash_amount,
            deadline,
            policy_id,
        }
        .publish(&env);
        Ok(id)
    }

    /// The buyer locks the cash.
    pub fn fund(env: Env, id: u64) -> Result<(), Error> {
        let mut t = Self::get(env.clone(), id)?;
        if t.state != State::Offered {
            return Err(Error::WrongState);
        }
        if env.ledger().timestamp() > t.deadline {
            return Err(Error::Expired);
        }
        t.buyer.require_auth();
        t.state = State::Funded;
        env.storage().persistent().set(&DataKey::Trade(id), &t);
        token::Client::new(&env, &t.cash).transfer(
            &t.buyer,
            env.current_contract_address(),
            &t.cash_amount,
        );
        Funded { id }.publish(&env);
        Ok(())
    }

    /// The value the proof must carry as its context: sha256(domain | this
    /// contract | id | seller | buyer | asset | asset_amount | cash |
    /// cash_amount | deadline | policy_id) with the first byte zeroed, so it
    /// fits the BLS12-381 scalar field. For the TravelRuleGate it is the
    /// `transfer_id` the agent evaluates on Midnight.
    pub fn context(env: Env, id: u64) -> Result<U256, Error> {
        let t = Self::get(env.clone(), id)?;
        let mut b = Bytes::from_slice(&env, CONTEXT_DOMAIN);
        b.append(&env.current_contract_address().to_xdr(&env));
        b.extend_from_array(&id.to_be_bytes());
        b.append(&t.seller.to_xdr(&env));
        b.append(&t.buyer.to_xdr(&env));
        b.append(&t.asset.to_xdr(&env));
        b.extend_from_array(&t.asset_amount.to_be_bytes());
        b.append(&t.cash.to_xdr(&env));
        b.extend_from_array(&t.cash_amount.to_be_bytes());
        b.extend_from_array(&t.deadline.to_be_bytes());
        b.extend_from_array(&t.policy_id.to_be_bytes());
        let mut h = env.crypto().sha256(&b).to_array();
        h[0] = 0;
        Ok(U256::from_be_bytes(&env, &Bytes::from_array(&env, &h)))
    }

    /// Settles with a Groth16 proof (Circom lane). Anyone may submit it.
    pub fn settle(env: Env, id: u64, proof: Proof, pub_signals: Vec<Fr>) -> Result<(), Error> {
        let (t, context) = Self::settleable(&env, id)?;
        // Traps (reverting everything) if the gate refuses.
        GateClient::new(&env, &Self::gate(env.clone())?).check_circom(
            &t.policy_id,
            &context,
            &proof,
            &pub_signals,
        );
        Self::swap(&env, id, t);
        Ok(())
    }

    /// Settles with a native Midnight proof (Midnight lane). Anyone may submit it.
    pub fn settle_midnight(
        env: Env,
        id: u64,
        proof: Bytes,
        hints: Vec<BytesN<96>>,
        statement: Vec<U256>,
    ) -> Result<(), Error> {
        let (t, context) = Self::settleable(&env, id)?;
        GateClient::new(&env, &Self::gate(env.clone())?).check_midnight(
            &t.policy_id,
            &context,
            &proof,
            &hints,
            &statement,
        );
        Self::swap(&env, id, t);
        Ok(())
    }

    /// After the deadline, returns each leg to whoever locked it.
    pub fn cancel(env: Env, id: u64) -> Result<(), Error> {
        let mut t = Self::get(env.clone(), id)?;
        let funded = match t.state {
            State::Offered => false,
            State::Funded => true,
            _ => return Err(Error::WrongState),
        };
        if env.ledger().timestamp() <= t.deadline {
            return Err(Error::NotExpired);
        }
        t.state = State::Cancelled;
        env.storage().persistent().set(&DataKey::Trade(id), &t);
        let me = env.current_contract_address();
        token::Client::new(&env, &t.asset).transfer(&me, &t.seller, &t.asset_amount);
        if funded {
            token::Client::new(&env, &t.cash).transfer(&me, &t.buyer, &t.cash_amount);
        }
        Cancelled { id }.publish(&env);
        Ok(())
    }
}

impl ComplianceDvp {
    fn settleable(env: &Env, id: u64) -> Result<(Trade, U256), Error> {
        let t = Self::get(env.clone(), id)?;
        if t.state != State::Funded {
            return Err(Error::WrongState);
        }
        if env.ledger().timestamp() > t.deadline {
            return Err(Error::Expired);
        }
        let context = Self::context(env.clone(), id)?;
        Ok((t, context))
    }

    /// Both legs in one call; a refused transfer (e.g. the security's issuer
    /// has not authorized the buyer) reverts the whole settlement.
    fn swap(env: &Env, id: u64, mut t: Trade) {
        t.state = State::Settled;
        env.storage().persistent().set(&DataKey::Trade(id), &t);
        let me = env.current_contract_address();
        token::Client::new(env, &t.asset).transfer(&me, &t.buyer, &t.asset_amount);
        token::Client::new(env, &t.cash).transfer(&me, &t.seller, &t.cash_amount);
        Settled { id }.publish(env);
    }
}

#[cfg(test)]
mod test;

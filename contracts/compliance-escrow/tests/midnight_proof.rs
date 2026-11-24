//! End to end with a REAL Midnight proof (ZKIR v2 circuit proved with the
//! ledger prover, Midnight SRS): real midnight-verifier, real gate (Midnight
//! lane), real escrow, a Stellar Asset Contract as testnet USDC.
//!
//! Circuit statement: `[binding_input, commitment, context]`. The policy pins
//! the commitment and requires `context == escrow.context(1)`. Addresses in
//! testutils are deterministic; if the setup changes, the failing test prints
//! the new context: regenerate with
//! `midnight-export zkir-context escrow-context <context> fixtures/midnight`.

use compliance_escrow::{ComplianceEscrow, ComplianceEscrowClient, State};
use compliance_gate::{ComplianceGate, ComplianceGateClient, MidnightPolicy, Pin};
use midnight_verifier::{MidnightVerifier, MidnightVerifierClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, BytesN, Env, Vec, U256,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/midnight/escrow-context/"
);

fn unhex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct World<'a> {
    env: Env,
    escrow: ComplianceEscrowClient<'a>,
    usdc: TokenClient<'a>,
    beneficiary: Address,
    proof: Bytes,
    hints: Vec<BytesN<96>>,
    statement: Vec<U256>,
}

fn world<'a>(from_wasm: bool) -> World<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().set_timestamp(1_795_900_100);
    let admin = Address::generate(&env);

    let mv_id = if from_wasm {
        let wasm = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/wasm32v1-none/release/midnight_verifier.wasm"
        ))
        .expect("build the wasm first: cargo build --release --target wasm32v1-none");
        env.register(wasm.as_slice(), (admin.clone(),))
    } else {
        env.register(MidnightVerifier, (admin.clone(),))
    };
    let mv = MidnightVerifierClient::new(&env, &mv_id.clone());

    let gate_id = env.register(
        ComplianceGate,
        (admin.clone(), Address::generate(&env), mv_id.clone()),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let usdc = TokenClient::new(&env, &sac.address());
    let payer = Address::generate(&env);
    StellarAssetClient::new(&env, &sac.address()).mint(&payer, &10_000_000_000);

    let escrow_id = env.register(ComplianceEscrow, (admin, gate_id));
    let escrow = ComplianceEscrowClient::new(&env, &escrow_id);
    let beneficiary = Address::generate(&env);
    let id = escrow.deposit(
        &payer,
        &beneficiary,
        &sac.address(),
        &1_000_000_000,
        &1_796_000_000,
        &1,
    );
    assert_eq!(id, 1);

    let ctx = escrow.context(&1);
    let mut ctx_be = [0u8; 32];
    ctx.to_be_bytes().copy_into_slice(&mut ctx_be);
    let regen = format!(
        "regenerate with: midnight-export zkir-context escrow-context {} fixtures/midnight",
        hex(&ctx_be)
    );
    let pi = std::fs::read_to_string(format!("{DIR}pi.hex")).expect(&regen);
    let mut statement = Vec::new(&env);
    for l in pi.lines() {
        let mut be: [u8; 32] = unhex(l.trim()).try_into().unwrap();
        be.reverse();
        statement.push_back(U256::from_be_bytes(&env, &Bytes::from_array(&env, &be)));
    }
    assert_eq!(
        statement.get(2).unwrap(),
        ctx,
        "fixture context is stale; {regen}"
    );
    let svk = std::fs::read(format!("{DIR}vk.svk")).unwrap();
    let vk_hash = mv.register_vk(&Bytes::from_slice(&env, &svk));

    let mut pins = Vec::new(&env);
    pins.push_back(Pin {
        index: 1,
        value: statement.get(1).unwrap(),
    });
    gate.set_midnight_policy(
        &1,
        &MidnightPolicy {
            vk_hash,
            statement_len: 3,
            pins,
            context_index: 2,
            valid_until: 1_796_000_000,
        },
    );

    let mut hints = Vec::new(&env);
    for l in std::fs::read_to_string(format!("{DIR}hints.hex"))
        .unwrap()
        .lines()
    {
        let b: [u8; 96] = unhex(l.trim()).try_into().unwrap();
        hints.push_back(BytesN::from_array(&env, &b));
    }
    let proof = Bytes::from_slice(&env, &std::fs::read(format!("{DIR}proof.bin")).unwrap());
    World {
        env,
        escrow,
        usdc,
        beneficiary,
        proof,
        hints,
        statement,
    }
}

#[test]
fn real_midnight_proof_releases_the_escrow() {
    let w = world(false);
    w.escrow
        .release_midnight(&1, &w.proof, &w.hints, &w.statement);
    assert_eq!(w.escrow.get(&1).state, State::Released);
    assert_eq!(w.usdc.balance(&w.beneficiary), 1_000_000_000);
}

#[test]
fn real_midnight_proof_releases_through_wasm_within_budget() {
    let w = world(true);
    w.env.cost_estimate().budget().reset_unlimited();
    w.escrow
        .release_midnight(&1, &w.proof, &w.hints, &w.statement);
    let b = w.env.cost_estimate().budget();
    println!(
        "release_midnight (verifier as wasm): cpu {} instructions, mem {} bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost()
    );
    assert!(
        b.cpu_instruction_cost() < 400_000_000,
        "over the per-transaction cap"
    );
    assert_eq!(w.usdc.balance(&w.beneficiary), 1_000_000_000);
}

#[test]
fn tampered_midnight_proof_keeps_funds_locked() {
    let w = world(false);
    let mut p: std::vec::Vec<u8> = std::vec::Vec::new();
    for i in 0..w.proof.len() {
        p.push(w.proof.get(i).unwrap());
    }
    let i = p.len() - 2 * 48 - 10;
    p[i] ^= 1;
    let bad = Bytes::from_slice(&w.env, &p);
    assert!(w
        .escrow
        .try_release_midnight(&1, &bad, &w.hints, &w.statement)
        .is_err());
    assert_eq!(w.escrow.get(&1).state, State::Funded);
    assert_eq!(w.usdc.balance(&w.beneficiary), 0);
}

#[test]
fn proof_for_another_escrow_is_refused() {
    let w = world(false);
    let mut s = w.statement.clone();
    s.set(2, s.get(2).unwrap().add(&U256::from_u32(&w.env, 1)));
    assert!(w
        .escrow
        .try_release_midnight(&1, &w.proof, &w.hints, &s)
        .is_err());
    assert_eq!(w.escrow.get(&1).state, State::Funded);
}

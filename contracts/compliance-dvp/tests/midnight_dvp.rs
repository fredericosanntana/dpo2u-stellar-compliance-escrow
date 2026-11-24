//! Delivery versus payment settled by a REAL Midnight proof (ZKIR v3 circuit,
//! ledger prover, Midnight SRS) through the gate's Midnight lane, with the
//! verifier as wasm: 10 units of a receivable token against 250 testnet USDC.
//!
//! Circuit statement `[binding_input, commitment, context]`, bound to
//! `dvp.context(1)`. Addresses in testutils are deterministic; if the setup
//! changes, the failing test prints the command that regenerates the fixture.

use compliance_dvp::{ComplianceDvp, ComplianceDvpClient, State};
use compliance_gate::{ComplianceGate, ComplianceGateClient, MidnightPolicy, Pin, CTX_FIELD};
use midnight_verifier::MidnightVerifierClient;
use soroban_sdk::{
    testutils::{Address as _, IssuerFlags, Ledger},
    token::{StellarAssetClient, TokenClient},
    Address, Bytes, BytesN, Env, Vec, U256,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/midnight/dvp-context/"
);
const WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release/midnight_verifier.wasm"
);

fn unhex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn real_midnight_proof_settles_delivery_versus_payment() {
    let Ok(wasm) = std::fs::read(WASM) else {
        eprintln!("skipped: build the wasm first");
        return;
    };
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().set_timestamp(1_795_900_100);
    let admin = Address::generate(&env);
    let mv_id = env.register(wasm.as_slice(), (admin.clone(),));
    let mv = MidnightVerifierClient::new(&env, &mv_id);
    let gate_id = env.register(
        ComplianceGate,
        (admin.clone(), Address::generate(&env), mv_id),
    );
    let gate = ComplianceGateClient::new(&env, &gate_id);

    let sec = env.register_stellar_asset_contract_v2(Address::generate(&env));
    sec.issuer().set_flag(IssuerFlags::RevocableFlag);
    let security = TokenClient::new(&env, &sec.address());
    let usdc_sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let usdc = TokenClient::new(&env, &usdc_sac.address());
    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);
    StellarAssetClient::new(&env, &sec.address()).mint(&seller, &100);
    StellarAssetClient::new(&env, &usdc_sac.address()).mint(&buyer, &10_000_000_000);

    let dvp_id = env.register(ComplianceDvp, (gate_id,));
    let dvp = ComplianceDvpClient::new(&env, &dvp_id);
    let id = dvp.offer(
        &seller,
        &buyer,
        &sec.address(),
        &10,
        &usdc_sac.address(),
        &2_500_000_000,
        &1_796_000_000,
        &1,
    );
    dvp.fund(&id);

    let ctx = dvp.context(&id);
    let mut ctx_be = [0u8; 32];
    ctx.to_be_bytes().copy_into_slice(&mut ctx_be);
    let ctx_hex: String = ctx_be.iter().map(|b| format!("{b:02x}")).collect();
    let regen = format!(
        "regenerate with: midnight-export zkir-context dvp-context {ctx_hex} fixtures/midnight"
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
            context_encoding: CTX_FIELD,
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

    // the issuer freezes the buyer: a valid proof is not enough
    StellarAssetClient::new(&env, &sec.address()).set_authorized(&buyer, &false);
    assert!(dvp
        .try_settle_midnight(&id, &proof, &hints, &statement)
        .is_err());
    assert_eq!(dvp.get(&id).state, State::Funded);
    StellarAssetClient::new(&env, &sec.address()).set_authorized(&buyer, &true);

    env.cost_estimate().budget().reset_unlimited();
    dvp.settle_midnight(&id, &proof, &hints, &statement);
    let b = env.cost_estimate().budget();
    println!(
        "settle_midnight (verifier as wasm): cpu {} instructions, mem {} bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost()
    );
    assert!(b.cpu_instruction_cost() < 400_000_000);
    assert_eq!(dvp.get(&id).state, State::Settled);
    assert_eq!(security.balance(&buyer), 10);
    assert_eq!(usdc.balance(&seller), 2_500_000_000);
}

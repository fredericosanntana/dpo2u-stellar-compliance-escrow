//! The REAL TravelRuleGate v12 `evaluateTransfer` proof captured on Midnight
//! preview (fixtures/midnight/travel-rule-gate-v12) through the gate's
//! Midnight lane, with the verifier as wasm. The capture's `transfer_id`
//! stands for the escrow context (`CTX_COMPACT_BYTES32` at 202..203, the key
//! of the `status` insert).
//!
//! Statement positions (0-based). Compact `Bytes<32>` values are
//! [last byte, first 31 bytes LE]: transfer_id 27 (member) and 202 (status
//! insert), policy_hash 290, list_root 311, pepper_commit 373, provider_id
//! 114. Verdict: status 208 (1 = PASS, 2 = FAIL, checked against a real FAIL
//! capture), fail_reason 228. evaluateTransfer has a fixed statement layout
//! (417 values) for PASS and FAIL.

use compliance_gate::{
    ComplianceGate, ComplianceGateClient, Error, MidnightPolicy, Pin, CTX_COMPACT_BYTES32,
};
use midnight_verifier::MidnightVerifierClient;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec, U256};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/midnight/travel-rule-gate-v12/"
);
const WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release/midnight_verifier.wasm"
);
/// "tr-v12-cap2-20261124T014017", zero padded (public in the Midnight tx).
const TRANSFER_ID: &str = "74722d7631322d636170322d3230323631313234543031343031370000000000";
const PINNED: [u32; 8] = [290, 291, 311, 312, 373, 374, 114, 115];
const STATUS: u32 = 208;
const FAIL_REASON: u32 = 228;

fn unhex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct T {
    env: Env,
    gate: ComplianceGateClient<'static>,
    proof: Bytes,
    hints: Vec<BytesN<96>>,
    statement: Vec<U256>,
    ctx: U256,
}

fn setup() -> Option<T> {
    let wasm = std::fs::read(WASM).ok()?;
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let mv_id = env.register(wasm.as_slice(), (admin.clone(),));
    let mv = MidnightVerifierClient::new(&env, &mv_id);
    let svk = std::fs::read(format!("{DIR}vk.svk")).unwrap();
    let vk_hash = mv.register_vk(&Bytes::from_slice(&env, &svk));
    let gate_id = env.register(ComplianceGate, (admin, Address::generate(&env), mv_id));
    let gate = ComplianceGateClient::new(&env, &gate_id);

    let mut statement = Vec::new(&env);
    for l in std::fs::read_to_string(format!("{DIR}pi.hex"))
        .unwrap()
        .lines()
    {
        let mut be: [u8; 32] = unhex(l.trim()).try_into().unwrap();
        be.reverse();
        statement.push_back(U256::from_be_bytes(&env, &Bytes::from_array(&env, &be)));
    }
    let mut pins = Vec::new(&env);
    for i in PINNED {
        pins.push_back(Pin {
            index: i,
            value: statement.get(i).unwrap(),
        });
    }
    // verdict PASS with no fail reason
    pins.push_back(Pin {
        index: STATUS,
        value: U256::from_u32(&env, 1),
    });
    pins.push_back(Pin {
        index: FAIL_REASON,
        value: U256::from_u32(&env, 0),
    });
    gate.set_midnight_policy(
        &1,
        &MidnightPolicy {
            vk_hash,
            statement_len: statement.len(),
            pins,
            context_index: 202,
            context_encoding: CTX_COMPACT_BYTES32,
            valid_until: u64::MAX,
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
    let id: [u8; 32] = unhex(TRANSFER_ID).try_into().unwrap();
    let ctx = U256::from_be_bytes(&env, &Bytes::from_array(&env, &id));
    Some(T {
        env,
        gate,
        proof,
        hints,
        statement,
        ctx,
    })
}

#[test]
fn real_travel_rule_gate_proof_passes_the_midnight_lane() {
    let Some(t) = setup() else {
        eprintln!("skipped: build the wasm first");
        return;
    };
    t.env.cost_estimate().budget().reset_unlimited();
    assert!(t
        .gate
        .check_midnight(&1, &t.ctx, &t.proof, &t.hints, &t.statement));
    let b = t.env.cost_estimate().budget();
    println!(
        "check_midnight (real TravelRuleGate v12): cpu {} instructions, mem {} bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost()
    );
    assert!(b.cpu_instruction_cost() < 400_000_000);
}

#[test]
fn real_proof_is_refused_for_another_transfer_or_policy() {
    let Some(t) = setup() else {
        return;
    };
    let other = t.ctx.add(&U256::from_u32(&t.env, 1));
    assert_eq!(
        t.gate
            .try_check_midnight(&1, &other, &t.proof, &t.hints, &t.statement),
        Err(Ok(Error::ContextMismatch))
    );
    // a statement claiming another rule pack is refused before verification
    let mut s = t.statement.clone();
    s.set(291, s.get(291).unwrap().add(&U256::from_u32(&t.env, 1)));
    assert_eq!(
        t.gate
            .try_check_midnight(&1, &t.ctx, &t.proof, &t.hints, &s),
        Err(Ok(Error::PinMismatch))
    );
    // a FAIL verdict (status 2, reason 4) is refused by the pins
    let mut s = t.statement.clone();
    s.set(STATUS, U256::from_u32(&t.env, 2));
    s.set(FAIL_REASON, U256::from_u32(&t.env, 4));
    assert_eq!(
        t.gate
            .try_check_midnight(&1, &t.ctx, &t.proof, &t.hints, &s),
        Err(Ok(Error::PinMismatch))
    );
    // a statement edited outside the pins fails the proof itself
    let mut s = t.statement.clone();
    s.set(40, s.get(40).unwrap().add(&U256::from_u32(&t.env, 1)));
    assert_eq!(
        t.gate
            .try_check_midnight(&1, &t.ctx, &t.proof, &t.hints, &s),
        Err(Ok(Error::InvalidProof))
    );
}

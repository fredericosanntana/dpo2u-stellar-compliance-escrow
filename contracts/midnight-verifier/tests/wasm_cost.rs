//! Same real proof as the unit tests, but through the release WASM so the
//! budget includes the VM instructions (Blake2b, SVK decoding, the verifier
//! loop), not only host calls. Build first:
//! `cargo build --release --target wasm32v1-none -p midnight-verifier`.
use midnight_verifier::MidnightVerifierClient;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec, U256};

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
fn poseidon_through_wasm() {
    run("poseidon");
}

/// ZKIR v2 circuit proven by the ledger's own prover (midnight-zkir 2.2.0)
/// with Midnight's SRS: the Compact pipeline.
#[test]
fn zkir_hash_through_wasm() {
    run("zkir-hash");
}

/// Real TravelRuleGate v12 `evaluateTransfer` proof captured on Midnight
/// preview (proof-server 9.0.1), 417 statement values.
#[test]
fn travel_rule_gate_v12_through_wasm() {
    run("travel-rule-gate-v12");
}

fn run(name: &str) {
    let Ok(wasm) = std::fs::read(WASM) else {
        eprintln!("skipped: {WASM} not built");
        return;
    };
    let dir = format!(
        "{}/../../fixtures/midnight/{name}/",
        env!("CARGO_MANIFEST_DIR")
    );
    let svk = std::fs::read(format!("{dir}vk.svk")).unwrap();
    let proof = std::fs::read(format!("{dir}proof.bin")).unwrap();
    let pi = std::fs::read_to_string(format!("{dir}pi.hex")).unwrap();
    let hints = std::fs::read_to_string(format!("{dir}hints.hex")).unwrap();

    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(wasm.as_slice(), (admin,));
    let c = MidnightVerifierClient::new(&env, &id);
    let vk = c.register_vk(&Bytes::from_slice(&env, &svk));
    let mut h = Vec::new(&env);
    for l in hints.lines() {
        let b: [u8; 96] = unhex(l.trim()).try_into().unwrap();
        h.push_back(BytesN::from_array(&env, &b));
    }
    let mut s = Vec::new(&env);
    for l in pi.lines() {
        let mut be: [u8; 32] = unhex(l.trim()).try_into().unwrap();
        be.reverse();
        s.push_back(U256::from_be_bytes(&env, &Bytes::from_array(&env, &be)));
    }
    env.cost_estimate().budget().reset_unlimited();
    assert!(c.verify(&vk, &Bytes::from_slice(&env, &proof), &h, &s));
    let b = env.cost_estimate().budget();
    if std::env::var("BUDGET_DETAIL").is_ok() {
        println!("{b}");
    }
    println!(
        "wasm midnight verify [{name}]: cpu {} instructions, mem {} bytes",
        b.cpu_instruction_cost(),
        b.memory_bytes_cost()
    );
    assert!(
        b.cpu_instruction_cost() < 400_000_000,
        "over the per-transaction cap"
    );
}

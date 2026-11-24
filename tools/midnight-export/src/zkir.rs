//! Compact circuits: ZKIR + keys + `ProofPreimage` -> proof and statement
//! with the ledger's own prover (`midnight-zkir`, `midnight-transient-crypto`),
//! then the same export and checks as the Poseidon example.

use std::{borrow::Cow, fs, io::Cursor, path::Path, sync::Arc};

use group::{prime::PrimeCurveAffine, Curve};
use midnight_curves::G2Affine;
use midnight_proofs::utils::SerdeFormat;
use midnight_serialize::{tagged_deserialize, tagged_serialize, Deserializable, Serializable};
use midnight_transient_crypto::{
    curve::Fr,
    proofs::{
        KeyLocation, ParamsProver, ParamsProverProvider, Proof, ProofPreimage, VerifierKey, Zkir,
        PARAMS_VERIFIER,
    },
};
use midnight_zk_stdlib::MidnightVK;
use midnight_zkir::IrSource;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Midnight's public parameters (`bls_midnight_2p{k}`, what the proof server
/// and the ledger use; NOT the same tau as `bls_filecoin_2p19`). Read from
/// `MIDNIGHT_PARAMS_DIR`, falling back to the `bls_midnight_2p14` that ships
/// inside midnight-transient-crypto, downsized.
pub fn midnight_srs(
    k: u32,
) -> midnight_proofs::poly::kzg::params::ParamsKZG<midnight_curves::Bls12> {
    let dir = std::env::var("MIDNIGHT_PARAMS_DIR").unwrap_or_default();
    let exact = Path::new(&dir).join(format!("bls_midnight_2p{k}"));
    let (path, downsize) = if !dir.is_empty() && exact.exists() {
        (exact, false)
    } else {
        assert!(k <= 14, "k={k}: set MIDNIGHT_PARAMS_DIR with bls_midnight_2p{k} (https://srs.midnight.network/)");
        (Path::new(BUNDLED_2P14).to_path_buf(), k < 14)
    };
    let f = std::io::BufReader::new(
        fs::File::open(&path).unwrap_or_else(|_| panic!("{}", path.display())),
    );
    let mut p = ParamsProver::read(f).expect("params").0.as_ref().clone();
    if downsize {
        p.downsize(k);
    }
    p
}

const BUNDLED_2P14: &str = env!("MIDNIGHT_2P14");

pub struct Srs;

impl ParamsProverProvider for Srs {
    async fn get_params(&self, k: u8) -> std::io::Result<ParamsProver> {
        Ok(ParamsProver(Arc::new(midnight_srs(k as u32))))
    }
}

/// The ledger's `VerifierKey` is a length-prefixed `MidnightVK` in
/// `SerdeFormat::Processed`.
pub fn midnight_vk(vk: &VerifierKey) -> MidnightVK {
    let mut buf = Vec::new();
    Serializable::serialize(vk, &mut buf).unwrap();
    let mut r: &[u8] = &buf;
    let len = <u64 as Deserializable>::deserialize(&mut r, 0).unwrap() as usize;
    assert_eq!(len, r.len(), "verifier key length prefix");
    let mvk = MidnightVK::read(&mut r, SerdeFormat::Processed).expect("MidnightVK");
    assert!(r.is_empty(), "trailing bytes after verifier key");
    mvk
}

fn le(f: &Fr) -> [u8; 32] {
    use ff::PrimeField;
    f.0.to_repr()
}

/// Proves `preimage`, checks it with the ledger verifier, exports, checks the
/// no_std verifier and writes `<out>/<name>/`.
pub fn run(
    name: &str,
    ir: &IrSource,
    pk: midnight_transient_crypto::proofs::ProverKey<IrSource>,
    vk: &VerifierKey,
    preimage: &ProofPreimage,
    out: &str,
) {
    let (proof, pis, _skips) =
        pollster::block_on(ir.prove(&mut ChaCha20Rng::from_seed([7; 32]), &Srs, pk, preimage))
            .expect("prove");
    export_checked(name, vk, &proof, &pis, out);
}

/// Checks `proof` against `pis` with the ledger verifier, exports the SVK,
/// checks the no_std verifier on valid and tampered inputs, writes
/// `<out>/<name>/` (plus the ledger's tagged key, for cross checks).
pub fn export_checked(name: &str, vk: &VerifierKey, proof: &Proof, pis: &[Fr], out: &str) {
    vk.verify(&PARAMS_VERIFIER, proof, pis.iter().copied())
        .expect("ledger verifier rejects the proof for this statement");
    let mvk = midnight_vk(vk);
    // [tau]_2 is the same for every k of a powers-of-tau SRS
    let s_g2 = midnight_srs(mvk.k().min(14) as u32)
        .verifier_params()
        .s_g2()
        .to_affine();
    let n_g2 = -G2Affine::generator();
    let svk = crate::export::export(mvk.vk(), 1, &s_g2, &n_g2);
    let pi: Vec<[u8; 32]> = pis.iter().map(le).collect();
    crate::report(name, &svk, &proof.0);
    crate::check(name, &svk, &pi, &proof.0);
    crate::write(out, name, &svk, &pi, &proof.0);
    let mut tagged = Vec::new();
    tagged_serialize(vk, &mut tagged).unwrap();
    fs::write(Path::new(out).join(name).join("ledger.verifier"), tagged).unwrap();
}

/// A ZKIR v3 circuit built here (Poseidon-based `transient_hash` plus a
/// public input), to exercise the Compact pipeline end to end without the
/// Compact compiler.
pub fn selftest(out: &str) {
    use midnight_transient_crypto::hash::transient_hash;
    let ir_raw = r#"{
       "version": { "major": 3, "minor": 1 },
       "do_communications_commitment": false,
       "inputs": [
           { "name": "%a", "type": "Scalar<BLS12-381>" },
           { "name": "%b", "type": "Scalar<BLS12-381>" },
           { "name": "%c", "type": "Scalar<BLS12-381>" }
       ],
       "outputs": [],
       "instructions": [
           { "op": "transient_hash", "output": "%h", "inputs": ["%a", "%b", "%c"] },
           { "op": "impact", "guard": "0x01", "inputs": ["%h"] }
       ]
    }"#;
    let ir = IrSource::load(ir_raw.as_bytes()).unwrap();
    let (pk, vk) = pollster::block_on(ir.keygen(&Srs)).unwrap();
    let x = transient_hash(&[1.into(), 2.into(), 3.into()]);
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![1.into(), 2.into(), 3.into()],
        private_transcript: vec![],
        public_transcript_inputs: vec![x],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };
    run("zkir-hash", &ir, pk, &vk, &preimage, out);
}

/// ZKIR v3 circuit for the escrow end-to-end test. Statement:
/// `[binding_input, transient_hash(a, b, c), context]`: the prover knows the
/// preimage of a pinned commitment (stands for the rule pack) and binds the
/// proof to one escrow `context` (big-endian hex, < r).
pub fn context(name: &str, context_be: &str, out: &str) {
    use ff::PrimeField;
    use midnight_transient_crypto::hash::transient_hash;
    let mut le: [u8; 32] = hex::decode(context_be)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    le.reverse();
    let ctx = Fr(Option::from(midnight_curves::Fq::from_repr(le)).expect("context >= r"));
    let ir_raw = r#"{
       "version": { "major": 3, "minor": 1 },
       "do_communications_commitment": false,
       "inputs": [
           { "name": "%a", "type": "Scalar<BLS12-381>" },
           { "name": "%b", "type": "Scalar<BLS12-381>" },
           { "name": "%c", "type": "Scalar<BLS12-381>" },
           { "name": "%ctx", "type": "Scalar<BLS12-381>" }
       ],
       "outputs": [],
       "instructions": [
           { "op": "transient_hash", "output": "%h", "inputs": ["%a", "%b", "%c"] },
           { "op": "impact", "guard": "0x01", "inputs": ["%h", "%ctx"] }
       ]
    }"#;
    let ir = IrSource::load(ir_raw.as_bytes()).unwrap();
    let (pk, vk) = pollster::block_on(ir.keygen(&Srs)).unwrap();
    let h = transient_hash(&[11.into(), 22.into(), 33.into()]);
    let preimage = ProofPreimage {
        binding_input: 42.into(),
        communications_commitment: None,
        inputs: vec![11.into(), 22.into(), 33.into(), ctx],
        private_transcript: vec![],
        public_transcript_inputs: vec![h, ctx],
        public_transcript_outputs: vec![],
        key_location: KeyLocation(Cow::Borrowed("builtin")),
    };
    run(name, &ir, pk, &vk, &preimage, out);
}

/// Compact artifacts from disk: `.bzkir` (or JSON `.zkir`), `.prover`,
/// `.verifier`, and a tagged `ProofPreimage`.
pub fn from_files(name: &str, ir: &Path, pk: &Path, vk: &Path, preimage: &Path, out: &str) {
    let ir = load_ir(ir);
    let pk = IrSource::load_prover_key_from_tagged(Cursor::new(fs::read(pk).unwrap())).unwrap();
    let vk: VerifierKey = tagged_deserialize(&fs::read(vk).unwrap()[..]).unwrap();
    let preimage: ProofPreimage = tagged_deserialize(&fs::read(preimage).unwrap()[..]).unwrap();
    run(name, &ir, pk, &vk, &preimage, out);
}

fn load_ir(p: &Path) -> IrSource {
    let b = fs::read(p).unwrap();
    if p.extension().is_some_and(|e| e == "zkir") {
        IrSource::load(&b[..]).unwrap()
    } else {
        IrSource::load_ir_from_tagged(Cursor::new(&b[..])).unwrap()
    }
}

/// The proof inside a proof-server `/prove` response (`ProofVersioned`).
pub fn read_proof_response(p: &Path) -> Proof {
    use midnight_ledger_v9::structure::ProofVersioned;
    let v: ProofVersioned = tagged_deserialize(&fs::read(p).unwrap()[..]).expect("proof-versioned");
    match v {
        ProofVersioned::V2(p) | ProofVersioned::V3(p) => p,
        #[allow(unreachable_patterns)]
        _ => panic!("unknown ProofVersioned"),
    }
}

fn read_pi_hex(p: &Path) -> Vec<Fr> {
    use ff::PrimeField;
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let le: [u8; 32] = hex::decode(l.trim()).unwrap().try_into().unwrap();
            Fr(Option::from(midnight_curves::Fq::from_repr(le)).expect("statement value >= r"))
        })
        .collect()
}

/// A captured proof (proof-server response) plus its public statement
/// (`pi.hex`, little-endian, one value per line): no prover, no preimage.
pub fn captured(name: &str, vk: &Path, response: &Path, pi: &Path, out: &str) {
    let vk: VerifierKey = tagged_deserialize(&fs::read(vk).unwrap()[..]).unwrap();
    let proof = read_proof_response(response);
    let pis = read_pi_hex(pi);
    export_checked(name, &vk, &proof, &pis, out);
}

/// Prints what the public files say: VK size and k, proof length.
pub fn inspect(vk: &Path, response: Option<&Path>) {
    let vk: VerifierKey = tagged_deserialize(&fs::read(vk).unwrap()[..]).unwrap();
    let mvk = midnight_vk(&vk);
    println!(
        "vk: k={} instance columns {} advice {} fixed {}",
        mvk.k(),
        mvk.vk().cs().num_instance_columns(),
        mvk.vk().cs().num_advice_columns(),
        mvk.vk().cs().num_fixed_columns()
    );
    let s_g2 = midnight_srs(14).verifier_params().s_g2().to_affine();
    let svk = crate::export::export(mvk.vk(), 1, &s_g2, &-G2Affine::generator());
    let proof = response
        .map(read_proof_response)
        .map(|p| p.0)
        .unwrap_or_default();
    crate::report("inspect", &svk, &proof);
}

/// Public statement of a `/prove` request, without publishing the request.
/// Runs on the machine that holds the request (it carries private
/// witnesses): reads the preimage and the binding-input override, proves
/// once locally (no network, no fee) to get the statement in the ledger's
/// own order, checks that the CAPTURED proof verifies against it, and writes
/// only `pi.hex`.
pub fn statement(request: &Path, response: &Path, params_note: &str, out_pi: &Path) {
    use midnight_ledger_v9::structure::ProofPreimageVersioned;
    use midnight_serialize::peek_tag;
    use midnight_transient_crypto::proofs::ProvingKeyMaterial;
    let req = fs::read(request).unwrap();
    let tag = peek_tag(&mut Cursor::new(&req[..])).unwrap_or_default();
    eprintln!("request tag: {tag}");
    type Req3 = (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    );
    type Req2 = (ProofPreimageVersioned, Option<ProvingKeyMaterial>);
    let (pre, keys, overwrite) = if let Ok((p, k, o)) = tagged_deserialize::<Req3>(&req[..]) {
        (p, k, o)
    } else if let Ok((p, k)) = tagged_deserialize::<Req2>(&req[..]) {
        (p, k, None)
    } else {
        panic!("unknown /prove request layout (tag {tag}); {params_note}");
    };
    let ProofPreimageVersioned::V2(pre) = pre else {
        panic!("unknown ProofPreimageVersioned")
    };
    let mut pre = (*pre).clone();
    if let Some(b) = overwrite {
        pre.binding_input = b;
    }
    let keys = keys.expect("request carries no key material");
    let ir = IrSource::load_ir_from_tagged(Cursor::new(&keys.ir_source[..])).unwrap();
    let pk = IrSource::load_prover_key_from_tagged(Cursor::new(&keys.prover_key[..])).unwrap();
    let vk: VerifierKey = tagged_deserialize(&keys.verifier_key[..]).unwrap();
    let (_, pis, _) =
        pollster::block_on(ir.prove(&mut ChaCha20Rng::from_seed([7; 32]), &Srs, pk, &pre))
            .expect("prove");
    let proof = read_proof_response(response);
    vk.verify(&PARAMS_VERIFIER, &proof, pis.iter().copied())
        .expect("captured proof does not verify against the derived statement");
    fs::write(
        out_pi,
        pis.iter()
            .map(|f| hex::encode(le(f)))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    println!(
        "captured proof verifies; wrote {} statement values to {}",
        pis.len(),
        out_pi.display()
    );
}

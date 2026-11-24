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
        KeyLocation, ParamsProver, ParamsProverProvider, ProofPreimage, VerifierKey, Zkir,
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
    vk.verify(&PARAMS_VERIFIER, &proof, pis.iter().copied())
        .expect("ledger verifier rejects its own proof");

    let mvk = midnight_vk(vk);
    let s_g2 = midnight_srs(mvk.k() as u32)
        .verifier_params()
        .s_g2()
        .to_affine();
    let n_g2 = -G2Affine::generator();
    let svk = crate::export::export(mvk.vk(), 1, &s_g2, &n_g2);
    let pi: Vec<[u8; 32]> = pis.iter().map(le).collect();
    crate::report(name, &svk, &proof.0);
    crate::check(name, &svk, &pi, &proof.0);
    crate::write(out, name, &svk, &pi, &proof.0);
    // the ledger's own key (tagged), for other verifiers' cross checks
    let mut tagged = Vec::new();
    tagged_serialize(vk, &mut tagged).unwrap();
    fs::write(Path::new(out).join(name).join("ledger.verifier"), tagged).unwrap();
}

/// A ZKIR v2 circuit built here (Poseidon-based `transient_hash` plus a
/// public input), to exercise the Compact pipeline end to end without the
/// Compact compiler.
pub fn selftest(out: &str) {
    use midnight_transient_crypto::hash::transient_hash;
    let ir_raw = r#"{
       "version": { "major": 2, "minor": 2 },
       "num_inputs": 3,
       "do_communications_commitment": false,
       "instructions": [
           { "op": "transient_hash", "inputs": [0, 1, 2] },
           { "op": "declare_pub_input", "var": 3 },
           { "op": "pi_skip", "guard": null, "count": 1}
       ]
    }"#;
    let ir = IrSource::load(ir_raw.as_bytes()).unwrap();
    let (pk, vk) = pollster::block_on(ir.v2_keygen(&Srs)).unwrap();
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

/// ZKIR v2 circuit for the escrow end-to-end test. Statement:
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
       "version": { "major": 2, "minor": 2 },
       "num_inputs": 4,
       "do_communications_commitment": false,
       "instructions": [
           { "op": "transient_hash", "inputs": [0, 1, 2] },
           { "op": "declare_pub_input", "var": 4 },
           { "op": "declare_pub_input", "var": 3 },
           { "op": "pi_skip", "guard": null, "count": 2}
       ]
    }"#;
    let ir = IrSource::load(ir_raw.as_bytes()).unwrap();
    let (pk, vk) = pollster::block_on(ir.v2_keygen(&Srs)).unwrap();
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
    let irb = fs::read(ir).unwrap();
    let ir = if ir.extension().is_some_and(|e| e == "zkir") {
        IrSource::load(&irb[..]).unwrap()
    } else {
        IrSource::load_ir_from_tagged(Cursor::new(&irb[..])).unwrap()
    };
    let pk = IrSource::load_prover_key_from_tagged(Cursor::new(fs::read(pk).unwrap())).unwrap();
    let vk: VerifierKey = tagged_deserialize(&fs::read(vk).unwrap()[..]).unwrap();
    let preimage: ProofPreimage = tagged_deserialize(&fs::read(preimage).unwrap()[..]).unwrap();
    run(name, &ir, pk, &vk, &preimage, out);
}


//! Builds a Midnight proof with midnight-zk-stdlib 2.4.0 (the ledger's
//! prover stack), exports its VK as SVK, and checks that the no_std
//! verifier agrees with `midnight_zk_stdlib::verify` on valid and tampered
//! inputs. Writes `<out>/<name>/{vk.svk,proof.bin,pi.hex}`.
//!
//! SRS: Midnight's `bls_midnight_2p{k}` (MIDNIGHT_PARAMS_DIR, else the
//! bundled 2p14). Not the Filecoin SRS: the ledger prover uses Midnight's.

mod export;
mod native;
mod zkir;

use std::{fs, path::Path};

use ff::{Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve};
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_curves::G2Affine;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_verifier_core::{verify, Error as VErr, Vk};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaCha8Rng;

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
struct PoseidonPreimage;

impl Relation for PoseidonPreimage {
    type Instance = F;
    type Witness = [F; 3];
    type Error = Error;

    fn format_instance(instance: &F) -> Result<Vec<F>, Error> {
        Ok(vec![*instance])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<F>,
        witness: Value<[F; 3]>,
    ) -> Result<(), Error> {
        let msg = std_lib.assign_many(layouter, &witness.transpose_array())?;
        let out = std_lib.poseidon(layouter, &msg)?;
        std_lib.constrain_as_public_input(layouter, &out)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_r: &mut R) -> std::io::Result<Self> {
        Ok(PoseidonPreimage)
    }
}

fn le(f: &F) -> [u8; 32] {
    f.to_repr()
}

fn hints(vk: &Vk, pi: &[[u8; 32]], proof: &[u8]) -> Vec<[u8; 96]> {
    let b = native::Native::default();
    verify(&b, vk, pi, proof).expect("valid proof");
    b.hints.into_inner()
}

pub fn check(name: &str, vk: &Vk, pi: &[[u8; 32]], proof: &[u8]) {
    let b = native::Native::default();
    assert_eq!(
        verify(&b, vk, pi, proof),
        Ok(()),
        "{name}: valid proof rejected"
    );

    // wrong public input
    let mut bad_pi = pi.to_vec();
    bad_pi[0][0] ^= 1;
    assert_eq!(
        verify(&b, vk, &bad_pi, proof),
        Err(VErr::PairingFailed),
        "{name}: wrong public input"
    );
    // flipped byte in every 32-byte window of the proof
    let mut rejected = 0;
    let mut by_pairing = 0;
    for i in (0..proof.len()).step_by(97) {
        let mut p = proof.to_vec();
        p[i] ^= 0x04;
        let r = verify(&b, vk, pi, &p);
        if r.is_err() {
            rejected += 1;
            if r == Err(VErr::PairingFailed) {
                by_pairing += 1;
            }
        } else {
            panic!("{name}: tampered proof accepted (byte {i})");
        }
    }
    assert_eq!(
        verify(&b, vk, pi, &proof[..proof.len() - 1]),
        Err(VErr::ProofTooShort)
    );
    let mut long = proof.to_vec();
    long.push(0);
    assert_eq!(verify(&b, vk, pi, &long), Err(VErr::TrailingBytes));
    println!("{name}: native no_std verifier OK; {rejected} tampered proofs rejected ({by_pairing} by the pairing check)");
}

pub fn report(name: &str, vk: &Vk, proof: &[u8]) {
    let bytes = vk.encode();
    assert_eq!(Vk::decode(&bytes).unwrap(), *vk, "SVK round trip");
    println!(
        "{name} k={}: advice {} fixed {} perm cols {} lookups {} trashcans {} gates {} ops {} sets {} proof {} B svk {} B",
        vk.k,
        vk.advice_phase.len(),
        vk.fixed_commitments.len(),
        vk.perm_columns.len(),
        vk.lookups.len(),
        vk.trashcans.len(),
        vk.gates.len(),
        vk.gates.iter().map(|g| g.0.len()).sum::<usize>(),
        vk.plan.len(),
        proof.len(),
        bytes.len()
    );
}

pub fn write(out: &str, name: &str, vk: &Vk, pi: &[[u8; 32]], proof: &[u8]) {
    let dir = Path::new(out).join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("vk.svk"), vk.encode()).unwrap();
    fs::write(dir.join("proof.bin"), proof).unwrap();
    fs::write(
        dir.join("pi.hex"),
        pi.iter().map(hex::encode).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    let h = hints(vk, pi, proof);
    fs::write(
        dir.join("hints.hex"),
        h.iter().map(hex::encode).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    println!(
        "wrote {} ({} statement values, {} hints)",
        dir.display(),
        pi.len(),
        h.len()
    );
}

fn poseidon(out: &str) {
    const K: u32 = 6;
    let srs = zkir::midnight_srs(K);
    let relation = PoseidonPreimage;
    let mvk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &mvk);

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);
    let proof = midnight_zk_stdlib::prove::<PoseidonPreimage, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, witness, OsRng,
    )
    .expect("prove");
    let vp = srs.verifier_params();
    midnight_zk_stdlib::verify::<PoseidonPreimage, blake2b_simd::State>(
        &vp, &mvk, &instance, None, &proof,
    )
    .expect("official verifier rejects its own proof");

    let s_g2 = vp.s_g2().to_affine();
    let n_g2 = -G2Affine::generator();
    let vk = export::export(mvk.vk(), 1, &s_g2, &n_g2);
    let pi: Vec<[u8; 32]> = PoseidonPreimage::format_instance(&instance)
        .unwrap()
        .iter()
        .map(le)
        .collect();
    report("poseidon", &vk, &proof);
    check("poseidon", &vk, &pi, &proof);
    write(out, "poseidon", &vk, &pi, &proof);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let usage = "usage: midnight-export poseidon <out> | zkir-selftest <out> | compact <name> <ir> <prover> <verifier> <preimage> <out>";
    match a.get(1).map(String::as_str) {
        Some("poseidon") => poseidon(&a[2]),
        Some("zkir-selftest") => zkir::selftest(&a[2]),
        Some("compact") if a.len() == 8 => zkir::from_files(
            &a[2],
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
            Path::new(&a[6]),
            &a[7],
        ),
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}

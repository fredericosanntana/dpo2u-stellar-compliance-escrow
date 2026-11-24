//! Native backend over midnight-curves, used to check the no_std verifier
//! against `midnight_zk_stdlib::verify`.

use ff::{Field, FromUniformBytes, PrimeField};
use group::{Curve, Group, GroupEncoding, UncompressedEncoding};
use midnight_curves::{
    pairing::{MillerLoopResult, MultiMillerLoop},
    Bls12, Fq, G1Affine, G1Projective, G2Affine, G2Prepared,
};
use midnight_verifier_core::Backend;

#[derive(Default)]
pub struct Native {
    /// Uncompressed forms of the non-identity points decompressed so far:
    /// the `hints` the Soroban verifier needs.
    pub hints: std::cell::RefCell<Vec<[u8; 96]>>,
}

fn g2_from(b: &[u8; 192]) -> G2Affine {
    let mut u = <G2Affine as UncompressedEncoding>::Uncompressed::default();
    u.as_mut().copy_from_slice(b);
    G2Affine::from_uncompressed(&u).unwrap()
}

impl Backend for Native {
    type Fr = Fq;
    type G1 = G1Projective;

    fn zero(&self) -> Fq {
        Fq::ZERO
    }
    fn one(&self) -> Fq {
        Fq::ONE
    }
    fn from_u64(&self, v: u64) -> Fq {
        Fq::from(v)
    }
    fn add(&self, a: &Fq, b: &Fq) -> Fq {
        a + b
    }
    fn sub(&self, a: &Fq, b: &Fq) -> Fq {
        a - b
    }
    fn mul(&self, a: &Fq, b: &Fq) -> Fq {
        a * b
    }
    fn inv(&self, a: &Fq) -> Option<Fq> {
        a.invert().into()
    }
    fn from_le_canonical(&self, b: &[u8; 32]) -> Option<Fq> {
        let mut r = <Fq as PrimeField>::Repr::default();
        r.as_mut().copy_from_slice(b);
        Fq::from_repr(r).into()
    }
    fn from_uniform(&self, b: &[u8; 64]) -> Fq {
        Fq::from_uniform_bytes(b)
    }
    fn g1_decompress(&self, c: &[u8; 48]) -> Option<G1Projective> {
        let mut r = <G1Projective as GroupEncoding>::Repr::default();
        r.as_mut().copy_from_slice(c);
        let p: Option<G1Projective> = G1Projective::from_bytes(&r).into();
        if let Some(p) = p {
            if !bool::from(p.is_identity()) {
                let mut u = [0u8; 96];
                u.copy_from_slice(p.to_affine().to_uncompressed().as_ref());
                self.hints.borrow_mut().push(u);
            }
        }
        p
    }
    fn g1_uncompressed(&self, u: &[u8; 96]) -> Option<G1Projective> {
        let mut r = <G1Affine as UncompressedEncoding>::Uncompressed::default();
        r.as_mut().copy_from_slice(u);
        Option::<G1Affine>::from(G1Affine::from_uncompressed(&r)).map(Into::into)
    }
    fn g1_generator(&self) -> G1Projective {
        G1Projective::generator()
    }
    fn g1_is_identity(&self, p: &G1Projective) -> bool {
        bool::from(p.is_identity())
    }
    fn msm(&self, bases: &[G1Projective], scalars: &[Fq]) -> G1Projective {
        bases
            .iter()
            .zip(scalars)
            .fold(G1Projective::identity(), |acc, (b, s)| acc + b * s)
    }
    fn pairing_check(
        &self,
        a1: &G1Projective,
        b1: &[u8; 192],
        a2: &G1Projective,
        b2: &[u8; 192],
    ) -> bool {
        let (p1, p2) = (a1.to_affine(), a2.to_affine());
        let (q1, q2) = (G2Prepared::from(g2_from(b1)), G2Prepared::from(g2_from(b2)));
        let r = <Bls12 as MultiMillerLoop>::multi_miller_loop(&[(&p1, &q1), (&p2, &q2)]);
        bool::from(r.final_exponentiation().is_identity())
    }
}

//! A `no_std` verifier for proofs made by `midnight-proofs` 0.8.2 through
//! `midnight-zk-stdlib` 2.4.0, the stack the Midnight ledger uses
//! (Plonk with permutation, lookup and trash arguments, KZG multi-open over
//! BLS12-381, Blake2b transcript, one committed instance column set to the
//! identity and one public instance column).
//!
//! The algorithm mirrors `midnight_proofs::plonk::verifier::prepare` and
//! `KZGCommitmentScheme::multi_prepare` step by step; it is generic over a
//! [`Backend`] so the same code runs natively (differential tests against the
//! real verifier) and inside a Soroban contract (host BLS12-381 functions).
//!
//! The algorithm is derived from midnight-proofs (MIT OR Apache-2.0; the
//! Midnight and halo2 authors).

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod transcript;
pub mod verify;
pub mod vk;

pub use verify::verify;
pub use vk::Vk;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The SVK blob is malformed.
    Decode,
    /// The VK shape is not one this verifier supports.
    Unsupported,
    /// The proof ended early.
    ProofTooShort,
    /// The proof has trailing bytes.
    TrailingBytes,
    /// A point in the proof is not a valid compressed G1 element.
    InvalidPoint,
    /// A scalar in the proof or the public inputs is not canonical.
    InvalidScalar,
    /// A division by zero (happens only with negligible probability for
    /// honest proofs).
    NotInvertible,
    /// The final pairing check failed: the proof is invalid.
    PairingFailed,
}

/// Curve and field operations the verifier needs. `Fr` is the BLS12-381
/// scalar field.
#[allow(clippy::wrong_self_convention)]
pub trait Backend {
    type Fr: Clone;
    type G1: Clone;

    fn zero(&self) -> Self::Fr;
    fn one(&self) -> Self::Fr;
    fn from_u64(&self, v: u64) -> Self::Fr;
    fn add(&self, a: &Self::Fr, b: &Self::Fr) -> Self::Fr;
    fn sub(&self, a: &Self::Fr, b: &Self::Fr) -> Self::Fr;
    fn mul(&self, a: &Self::Fr, b: &Self::Fr) -> Self::Fr;
    fn neg(&self, a: &Self::Fr) -> Self::Fr {
        self.sub(&self.zero(), a)
    }
    fn inv(&self, a: &Self::Fr) -> Option<Self::Fr>;
    fn pow(&self, a: &Self::Fr, mut e: u64) -> Self::Fr {
        let mut base = a.clone();
        let mut acc = self.one();
        while e > 0 {
            if e & 1 == 1 {
                acc = self.mul(&acc, &base);
            }
            base = self.mul(&base, &base);
            e >>= 1;
        }
        acc
    }
    /// 32 little-endian bytes, rejecting values `>= r`.
    fn from_le_canonical(&self, b: &[u8; 32]) -> Option<Self::Fr>;
    /// 64 little-endian bytes reduced mod `r` (`FromUniformBytes<64>`).
    fn from_uniform(&self, b: &[u8; 64]) -> Self::Fr;

    /// A compressed (48-byte, zcash flags) G1 element read from the proof.
    /// Must reject non-canonical encodings.
    fn g1_decompress(&self, c: &[u8; 48]) -> Option<Self::G1>;
    /// An uncompressed (96-byte) G1 element from the VK.
    fn g1_uncompressed(&self, u: &[u8; 96]) -> Option<Self::G1>;
    fn g1_generator(&self) -> Self::G1;
    fn g1_is_identity(&self, p: &Self::G1) -> bool;
    fn msm(&self, bases: &[Self::G1], scalars: &[Self::Fr]) -> Self::G1;
    /// `e(a1, b1) * e(a2, b2) == 1`, with G2 elements uncompressed.
    fn pairing_check(&self, a1: &Self::G1, b1: &[u8; 192], a2: &Self::G1, b2: &[u8; 192]) -> bool;
}

/// Compressed encoding of the G1 identity (zcash flags: compressed + infinity).
pub const G1_IDENTITY_COMPRESSED: [u8; 48] = {
    let mut a = [0u8; 48];
    a[0] = 0xc0;
    a
};

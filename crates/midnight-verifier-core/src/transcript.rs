//! `CircuitTranscript<blake2b_simd::State>` from midnight-proofs: one running
//! keyed Blake2b-512 state; `common` absorbs `0x01 || bytes`, a challenge
//! absorbs `0x00` and reads the 64-byte digest of the state so far.

use blake2b_simd::{Params, State};

use crate::{Backend, Error};

const PREFIX_CHALLENGE: u8 = 0;
const PREFIX_COMMON: u8 = 1;

pub struct Transcript<'a> {
    state: State,
    proof: &'a [u8],
    pos: usize,
}

impl<'a> Transcript<'a> {
    pub fn new(proof: &'a [u8]) -> Self {
        Transcript {
            state: Params::new()
                .hash_length(64)
                .key(b"Domain separator for transcript")
                .to_state(),
            proof,
            pos: 0,
        }
    }

    pub fn common(&mut self, bytes: &[u8]) {
        self.state.update(&[PREFIX_COMMON]);
        self.state.update(bytes);
    }

    pub fn squeeze<B: Backend>(&mut self, b: &B) -> B::Fr {
        self.state.update(&[PREFIX_CHALLENGE]);
        b.from_uniform(self.state.finalize().as_array())
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.pos + N;
        let s = self.proof.get(self.pos..end).ok_or(Error::ProofTooShort)?;
        self.pos = end;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn read_point<B: Backend>(&mut self, b: &B) -> Result<B::G1, Error> {
        let c: [u8; 48] = self.take()?;
        let p = b.g1_decompress(&c).ok_or(Error::InvalidPoint)?;
        self.common(&c);
        Ok(p)
    }

    pub fn read_scalar<B: Backend>(&mut self, b: &B) -> Result<B::Fr, Error> {
        let s: [u8; 32] = self.take()?;
        let f = b.from_le_canonical(&s).ok_or(Error::InvalidScalar)?;
        self.common(&s);
        Ok(f)
    }

    pub fn assert_empty(&self) -> Result<(), Error> {
        if self.pos == self.proof.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

//! Domain-separated hashing for the distributed tracer key generation and
//! the threshold-decryption Chaum-Pedersen proofs.
//!
//! All variable-length inputs are absorbed with an explicit length prefix so
//! that `H(a || b)` cannot collide with `H(a' || b')` for a different split
//! of the same byte string.

use crate::protocol::field::Fq;
use crate::protocol::group::Gt;
use sha2::{Digest, Sha256};

/// Domain-separation tag for the distributed key generation proof of
/// knowledge (`mu_k` in Figure `dist-keygen`).
pub const TAG_DKG: &[u8] = b"TAPS_TT/v1/dkg/tag";
/// Domain-separation tag for a Chaum-Pedersen challenge (Figure
/// `chaum-pederson`).
pub const TAG_CHAUM_PEDERSEN: &[u8] = b"TAPS_TT/v1/chaum-pedersen";

/// An incremental, domain-separated hash.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    /// Starts a transcript bound to `H(tag)`.
    pub fn new(tag: &[u8]) -> Transcript {
        let mut tag_hasher = Sha256::new();
        tag_hasher.update(tag);
        let tag_digest: [u8; 32] = tag_hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(tag_digest);
        Transcript { hasher }
    }

    /// Absorbs an unsigned integer.
    pub fn absorb_u64(&mut self, value: u64) -> &mut Transcript {
        self.hasher.update(value.to_be_bytes());
        self
    }

    /// Absorbs an index.
    pub fn absorb_usize(&mut self, value: usize) -> &mut Transcript {
        self.absorb_u64(value as u64)
    }

    /// Absorbs a group element.
    pub fn absorb_point(&mut self, point: &Gt) -> &mut Transcript {
        self.hasher.update(point.to_bytes());
        self
    }

    /// Finalises the transcript to a 32-byte digest.
    pub fn finalize_bytes(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }

    /// Finalises the transcript to a scalar in `Z_q`.
    pub fn finalize_scalar(&self) -> Fq {
        Fq::from_be_bytes_reduce(self.finalize_bytes())
    }
}

//! Group elements of secp256k1, including the identity `1_G`.
//!
//! `secp256k1::PublicKey` cannot represent the point at infinity, yet the
//! distributed tracer key generation and threshold decryption below produce
//! it naturally (an empty product of Feldman commitments, a Lagrange
//! recombination that cancels out, a decrypted attendance bit `b_i = 0`).
//! `Gt` adds that variant so those algorithms can be expressed directly
//! instead of panicking on `PublicKey::combine`.

use crate::protocol::field::Fq;
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::OnceLock;

static SECP_CONTEXT: OnceLock<Secp256k1<All>> = OnceLock::new();

/// Returns the process-wide secp256k1 context.
pub fn secp() -> &'static Secp256k1<All> {
    SECP_CONTEXT.get_or_init(Secp256k1::new)
}

/// An element of the secp256k1 group.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gt {
    /// The identity element `1_G`.
    Identity,
    /// A non-identity point.
    Point(PublicKey),
}

/// Encoding length of a group element (SEC1 compressed, or an all-zero
/// sentinel for the identity).
pub const GT_ENCODED_LEN: usize = 33;

impl Default for Gt {
    fn default() -> Self {
        Gt::Identity
    }
}

impl Gt {
    /// The group generator `g`.
    pub fn generator() -> Gt {
        Gt::Point(PublicKey::from_secret_key(
            secp(),
            &Fq::one().as_secret_key().expect("one is non-zero"),
        ))
    }

    /// The identity element `1_G`.
    pub fn identity() -> Gt {
        Gt::Identity
    }

    /// Returns `true` when the element is the identity.
    pub fn is_identity(&self) -> bool {
        matches!(self, Gt::Identity)
    }

    /// Computes `g^exponent`.
    pub fn base_mul(exponent: &Fq) -> Gt {
        match exponent.as_secret_key() {
            None => Gt::Identity,
            Some(sk) => Gt::Point(PublicKey::from_secret_key(secp(), &sk)),
        }
    }

    /// Wraps an existing public key.
    pub fn from_public_key(pk: &PublicKey) -> Gt {
        Gt::Point(*pk)
    }

    /// Returns the underlying public key, or `None` for the identity.
    pub fn to_public_key(&self) -> Option<PublicKey> {
        match self {
            Gt::Identity => None,
            Gt::Point(pk) => Some(*pk),
        }
    }

    /// Group operation (written multiplicatively in the protocol).
    pub fn add(&self, other: &Gt) -> Gt {
        match (self, other) {
            (Gt::Identity, _) => *other,
            (_, Gt::Identity) => *self,
            (Gt::Point(a), Gt::Point(b)) => match a.combine(b) {
                Ok(sum) => Gt::Point(sum),
                // `combine` fails exactly when the points cancel.
                Err(_) => Gt::Identity,
            },
        }
    }

    /// Inverse of the group element.
    pub fn neg(&self) -> Gt {
        match self {
            Gt::Identity => Gt::Identity,
            Gt::Point(pk) => Gt::Point(pk.negate(secp())),
        }
    }

    /// Group subtraction, i.e. `self * other^{-1}`.
    pub fn sub(&self, other: &Gt) -> Gt {
        self.add(&other.neg())
    }

    /// Scalar multiplication, i.e. `self^exponent`.
    pub fn mul(&self, exponent: &Fq) -> Gt {
        match (self, exponent.as_tweak()) {
            (Gt::Identity, _) => Gt::Identity,
            (_, None) => Gt::Identity,
            (Gt::Point(pk), Some(tweak)) => match pk.mul_tweak(secp(), &tweak) {
                Ok(product) => Gt::Point(product),
                Err(_) => Gt::Identity,
            },
        }
    }

    /// Product of a slice of group elements.
    pub fn product(elements: &[Gt]) -> Gt {
        elements
            .iter()
            .fold(Gt::Identity, |acc, element| acc.add(element))
    }

    /// Fixed-width encoding: the identity is 33 zero bytes, every other
    /// element is its SEC1 compressed encoding (which always starts with
    /// `0x02` or `0x03`, so the encodings never collide).
    pub fn to_bytes(&self) -> [u8; GT_ENCODED_LEN] {
        match self {
            Gt::Identity => [0u8; GT_ENCODED_LEN],
            Gt::Point(pk) => pk.serialize(),
        }
    }

    /// Inverse of [`Gt::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Gt, String> {
        if bytes.len() != GT_ENCODED_LEN {
            return Err(format!(
                "group element must be {} bytes, got {}",
                GT_ENCODED_LEN,
                bytes.len()
            ));
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(Gt::Identity);
        }
        PublicKey::from_slice(bytes)
            .map(Gt::Point)
            .map_err(|e| format!("invalid group element: {}", e))
    }
}

/// Converts a secret key into a scalar.
pub fn secret_key_to_fq(sk: &SecretKey) -> Fq {
    Fq::from_be_bytes(sk.secret_bytes()).expect("secret keys are reduced")
}

impl Serialize for Gt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().to_vec().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Gt {
    fn deserialize<D>(deserializer: D) -> Result<Gt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Gt::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_neutral() {
        let g = Gt::generator();
        assert_eq!(g.add(&Gt::identity()), g);
        assert_eq!(g.sub(&g), Gt::identity());
    }

    #[test]
    fn round_trip_bytes() {
        let g = Gt::generator();
        assert_eq!(Gt::from_bytes(&g.to_bytes()).unwrap(), g);
        assert_eq!(Gt::from_bytes(&Gt::identity().to_bytes()).unwrap(), Gt::identity());
    }
}

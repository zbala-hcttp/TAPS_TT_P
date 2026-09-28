//! Scalar arithmetic in `Z_q`, where `q` is the order of the secp256k1 group.
//!
//! The `secp256k1` crate exposes scalar arithmetic only through `SecretKey`,
//! which by construction can never represent `0`. The distributed tracer key
//! generation and threshold decryption below however rely on zero scalars
//! (Lagrange coefficients can legitimately land on values whose sum is zero,
//! and polynomial coefficients need a representable zero too). `Fq` therefore
//! wraps `SecretKey` with an explicit `Zero` variant so that the full field is
//! representable.

use rand::RngCore;
use rand::rngs::OsRng;
use secp256k1::{Scalar, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Order `q` of the secp256k1 group, big-endian.
pub const GROUP_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `q - 2`, the exponent used for inversion via Fermat's little theorem.
const ORDER_MINUS_TWO: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
];

/// An element of `Z_q`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fq {
    /// The additive identity `0`.
    Zero,
    /// A non-zero residue, held as a `SecretKey` so the audited constant-time
    /// arithmetic of `libsecp256k1` can be reused.
    NonZero(SecretKey),
}

impl fmt::Debug for Fq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; 32] = self.to_be_bytes();
        write!(f, "Fq(")?;
        for byte in bytes.iter().take(4) {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "..)")
    }
}

impl Default for Fq {
    fn default() -> Self {
        Fq::Zero
    }
}

/// Compares two big-endian 256-bit integers.
fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Computes `a - b` for big-endian 256-bit integers, assuming `a >= b`.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out: [u8; 32] = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff: i16 = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

impl Fq {
    /// The additive identity.
    pub fn zero() -> Fq {
        Fq::Zero
    }

    /// The multiplicative identity.
    pub fn one() -> Fq {
        Fq::from_u64(1)
    }

    /// Returns `true` when the scalar is `0`.
    pub fn is_zero(&self) -> bool {
        matches!(self, Fq::Zero)
    }

    /// Lifts a small integer into `Z_q`.
    pub fn from_u64(value: u64) -> Fq {
        if value == 0 {
            return Fq::Zero;
        }
        let mut bytes: [u8; 32] = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        Fq::NonZero(SecretKey::from_byte_array(bytes).expect("small integer is a valid scalar"))
    }

    /// Interprets `bytes` as a big-endian integer and reduces it modulo `q`.
    ///
    /// Because `2^256 < 2q`, a single conditional subtraction suffices; the
    /// loop is kept for clarity and costs nothing.
    pub fn from_be_bytes_reduce(bytes: [u8; 32]) -> Fq {
        let mut value: [u8; 32] = bytes;
        while cmp_be(&value, &GROUP_ORDER) != std::cmp::Ordering::Less {
            value = sub_be(&value, &GROUP_ORDER);
        }
        match SecretKey::from_byte_array(value) {
            Ok(sk) => Fq::NonZero(sk),
            Err(_) => Fq::Zero,
        }
    }

    /// Parses a canonical big-endian encoding, rejecting values `>= q`.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Fq, String> {
        if cmp_be(&bytes, &GROUP_ORDER) != std::cmp::Ordering::Less {
            return Err("scalar is not reduced modulo the group order".to_string());
        }
        match SecretKey::from_byte_array(bytes) {
            Ok(sk) => Ok(Fq::NonZero(sk)),
            Err(_) => Ok(Fq::Zero),
        }
    }

    /// Canonical big-endian encoding.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        match self {
            Fq::Zero => [0u8; 32],
            Fq::NonZero(sk) => sk.secret_bytes(),
        }
    }

    /// Samples a uniformly random non-zero scalar from the OS entropy source.
    pub fn random() -> Fq {
        let mut rng: OsRng = OsRng;
        let mut bytes: [u8; 32] = [0u8; 32];
        loop {
            rng.fill_bytes(&mut bytes);
            if let Ok(sk) = SecretKey::from_byte_array(bytes) {
                return Fq::NonZero(sk);
            }
        }
    }

    /// Returns the underlying `SecretKey`, or `None` for zero.
    pub fn as_secret_key(&self) -> Option<SecretKey> {
        match self {
            Fq::Zero => None,
            Fq::NonZero(sk) => Some(*sk),
        }
    }

    /// Returns the value as a `secp256k1::Scalar` tweak, or `None` for zero.
    pub fn as_tweak(&self) -> Option<Scalar> {
        match self {
            Fq::Zero => None,
            Fq::NonZero(sk) => Some(Scalar::from_be_bytes(sk.secret_bytes()).expect("valid scalar")),
        }
    }

    /// Field addition.
    pub fn add(&self, other: &Fq) -> Fq {
        match (self, other) {
            (Fq::Zero, _) => *other,
            (_, Fq::Zero) => *self,
            (Fq::NonZero(a), Fq::NonZero(_)) => {
                let tweak: Scalar = other.as_tweak().expect("non-zero");
                match a.add_tweak(&tweak) {
                    Ok(sum) => Fq::NonZero(sum),
                    // `add_tweak` fails exactly when the sum is zero mod q.
                    Err(_) => Fq::Zero,
                }
            }
        }
    }

    /// Field negation.
    pub fn neg(&self) -> Fq {
        match self {
            Fq::Zero => Fq::Zero,
            Fq::NonZero(sk) => Fq::NonZero(sk.negate()),
        }
    }

    /// Field subtraction.
    pub fn sub(&self, other: &Fq) -> Fq {
        self.add(&other.neg())
    }

    /// Field multiplication.
    pub fn mul(&self, other: &Fq) -> Fq {
        match (self, other) {
            (Fq::Zero, _) | (_, Fq::Zero) => Fq::Zero,
            (Fq::NonZero(a), Fq::NonZero(_)) => {
                let tweak: Scalar = other.as_tweak().expect("non-zero");
                match a.mul_tweak(&tweak) {
                    Ok(product) => Fq::NonZero(product),
                    // Cannot happen: `q` is prime, so a product of non-zero
                    // residues is non-zero.
                    Err(_) => Fq::Zero,
                }
            }
        }
    }

    /// Exponentiation by a big-endian exponent, via square-and-multiply.
    pub fn pow(&self, exponent_be: &[u8; 32]) -> Fq {
        let mut result: Fq = Fq::one();
        for byte in exponent_be.iter() {
            for bit in (0..8).rev() {
                result = result.mul(&result);
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Multiplicative inverse. Returns `None` for zero.
    pub fn invert(&self) -> Option<Fq> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(&ORDER_MINUS_TWO))
    }

    /// Field division. Returns `None` when `divisor` is zero.
    pub fn div(&self, divisor: &Fq) -> Option<Fq> {
        divisor.invert().map(|inverse| self.mul(&inverse))
    }

    /// Sums a slice of scalars.
    pub fn sum(values: &[Fq]) -> Fq {
        values.iter().fold(Fq::Zero, |acc, value| acc.add(value))
    }

    /// Returns `self^exponent` for a small exponent.
    pub fn pow_usize(&self, exponent: usize) -> Fq {
        let mut result: Fq = Fq::one();
        for _ in 0..exponent {
            result = result.mul(self);
        }
        result
    }
}

impl Serialize for Fq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_be_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Fq {
    fn deserialize<D>(deserializer: D) -> Result<Fq, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Fq::from_be_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invert_round_trips() {
        let a = Fq::random();
        let inverse = a.invert().expect("random scalar is non-zero");
        assert_eq!(a.mul(&inverse), Fq::one());
        assert!(Fq::zero().invert().is_none());
    }

    #[test]
    fn small_integers_add_as_expected() {
        let a = Fq::from_u64(2);
        let b = Fq::from_u64(3);
        assert_eq!(a.add(&b), Fq::from_u64(5));
        assert_eq!(a.mul(&b), Fq::from_u64(6));
        assert_eq!(a.sub(&a), Fq::zero());
    }
}

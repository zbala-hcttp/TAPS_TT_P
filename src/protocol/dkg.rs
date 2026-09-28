//! Distributed key generation among the `n_3` tracers (Figure
//! `dist-keygen`), and the threshold decryption / tracing that consumes it
//! (Figures `chaum-pederson`, `elgamal-decryption` and `trace`).
//!
//! A Feldman-style DKG: every tracer commits to a degree `t_e - 1`
//! polynomial, proves knowledge of its constant term, and distributes
//! evaluations. The qualified set `QUAL` publishes the group encryption key
//! `pk_e = prod_{w in QUAL} pk_w`; tracer `k` keeps the share
//! `sk_{e_k} = sum_{w in QUAL} s_{wk}` with verification key
//! `vk_k = g^{sk_{e_k}}`.
//!
//! Party indices are 1-based because the secret lives at `f(0)`.

use crate::protocol::dkg_hash::{TAG_CHAUM_PEDERSEN, TAG_DKG, Transcript};
use crate::protocol::field::Fq;
use crate::protocol::group::Gt;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What tracer `k` broadcasts in step 6 of the figure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgBroadcast {
    /// 1-based index `k` of the broadcasting tracer.
    pub index: usize,
    /// `pk_k = g^{s_k}`.
    pub pk: Gt,
    /// Feldman commitments `A_k = {A_kl}` to the polynomial coefficients.
    pub commitments: Vec<Gt>,
    /// Nonce commitment `R_k` of the proof of knowledge.
    pub nonce_commitment: Gt,
    /// Response `mu_k` of the proof of knowledge.
    pub mu: Fq,
}

/// The private state of tracer `k` during the DKG.
pub struct DkgParticipant {
    /// 1-based index of this tracer.
    pub index: usize,
    /// Reconstruction threshold `t_e`.
    pub threshold: usize,
    /// Total number of tracers `n_3`.
    pub total: usize,
    /// Polynomial coefficients `a_{k0}, ..., a_{k(t_e-1)}`.
    coefficients: Vec<Fq>,
    /// The broadcast this tracer produced.
    pub broadcast: DkgBroadcast,
}

/// The output of the DKG for one tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerKeyShare {
    /// 1-based index of this tracer.
    pub index: usize,
    /// Own polynomial secret `s_k = f_k(0)`.
    pub s: Fq,
    /// Own public value `pk_k = g^{s_k}`.
    pub pk: Gt,
    /// Threshold decryption share `sk_{e_k}`.
    pub sk_e: Fq,
    /// Verification key `vk_k = g^{sk_{e_k}}`.
    pub vk: Gt,
    /// Group encryption key `pk_e`.
    pub pk_e: Gt,
    /// Qualified set, sorted ascending.
    pub qual: Vec<usize>,
    /// Reconstruction threshold `t_e`.
    pub threshold: usize,
}

impl TracerKeyShare {
    /// `pk_e` as a `secp256k1::PublicKey`, for use with the rest of the
    /// protocol (which represents public keys that way). `pk_e` is a sum of
    /// at least one non-identity public key, so it is never the identity in
    /// an honest run.
    pub fn pk_e_as_public_key(&self) -> PublicKey {
        self.pk_e
            .to_public_key()
            .expect("pk_e is a product of real tracer public keys and cannot be the identity")
    }
}

/// Challenge `h_k = H(k || H(tag) || pk_k || R_k)` of the proof of knowledge.
fn pok_challenge(index: usize, pk: &Gt, nonce_commitment: &Gt) -> Fq {
    let mut transcript = Transcript::new(TAG_DKG);
    transcript.absorb_usize(index);
    transcript.absorb_point(pk);
    transcript.absorb_point(nonce_commitment);
    transcript.finalize_scalar()
}

/// Evaluates `f(x) = sum_l coefficients[l] * x^l`.
fn evaluate(coefficients: &[Fq], x: &Fq) -> Fq {
    // Horner's rule.
    let mut accumulator: Fq = Fq::zero();
    for coefficient in coefficients.iter().rev() {
        accumulator = accumulator.mul(x).add(coefficient);
    }
    accumulator
}

impl DkgParticipant {
    /// `DistributedKeyGen(tag, k, t_e, n_3)`, steps 1 to 6.
    ///
    /// `index` is 1-based and must satisfy `1 <= index <= total`.
    pub fn new(index: usize, threshold: usize, total: usize) -> Result<DkgParticipant, String> {
        if total == 0 {
            return Err("the tracer count n_3 must be at least 1".to_string());
        }
        if threshold == 0 || threshold > total {
            return Err(format!(
                "the threshold t_e must satisfy 1 <= t_e <= n_3, got t_e = {} and n_3 = {}",
                threshold, total
            ));
        }
        if index == 0 || index > total {
            return Err(format!(
                "tracer indices are 1-based and must be at most n_3 = {}, got {}",
                total, index
            ));
        }

        // 1. Sample a degree t_e - 1 polynomial.
        let coefficients: Vec<Fq> = (0..threshold).map(|_| Fq::random()).collect();

        // 2. Feldman commitments A_kl = g^{a_kl}.
        let commitments: Vec<Gt> = coefficients.iter().map(Gt::base_mul).collect();

        // 3. s_k = f_k(0) = a_{k0}, pk_k = g^{s_k}.
        let s: Fq = coefficients[0];
        let pk: Gt = commitments[0];

        // 4.-5. Proof of knowledge of s_k.
        let r: Fq = Fq::random();
        let nonce_commitment: Gt = Gt::base_mul(&r);
        let h: Fq = pok_challenge(index, &pk, &nonce_commitment);
        let mu: Fq = r.add(&h.mul(&s));

        Ok(DkgParticipant {
            index,
            threshold,
            total,
            coefficients,
            broadcast: DkgBroadcast {
                index,
                pk,
                commitments,
                nonce_commitment,
                mu,
            },
        })
    }

    /// Own polynomial secret `s_k = f_k(0)`.
    pub fn secret(&self) -> Fq {
        self.coefficients[0]
    }

    /// Step 8: the share `s_{kw} = f_k(w)` destined for tracer `w`.
    pub fn share_for(&self, w: usize) -> Fq {
        evaluate(&self.coefficients, &Fq::from_u64(w as u64))
    }

    /// Step 10-11: combines the qualified broadcasts and the shares this
    /// tracer received into its long-lived key material.
    ///
    /// `received_shares` maps a dealer index `w` to `s_{wk}`; it must contain
    /// an entry for every member of `qual`, including this tracer itself.
    pub fn finalize(
        &self,
        qual: &[usize],
        broadcasts: &BTreeMap<usize, DkgBroadcast>,
        received_shares: &BTreeMap<usize, Fq>,
    ) -> Result<TracerKeyShare, String> {
        if qual.is_empty() {
            return Err("the qualified set is empty; the DKG failed".to_string());
        }
        if qual.len() < self.threshold {
            return Err(format!(
                "the qualified set has {} members, fewer than the threshold t_e = {}",
                qual.len(),
                self.threshold
            ));
        }

        let mut sorted_qual: Vec<usize> = qual.to_vec();
        sorted_qual.sort_unstable();
        sorted_qual.dedup();

        // 10. pk_e = prod_{w in QUAL} pk_w
        let mut pk_e: Gt = Gt::identity();
        // 11. sk_{e_k} = sum_{w in QUAL} s_{wk}, vk_k = g^{sk_{e_k}}
        let mut sk_e: Fq = Fq::zero();

        for w in sorted_qual.iter() {
            let broadcast: &DkgBroadcast = broadcasts
                .get(w)
                .ok_or_else(|| format!("missing broadcast from qualified tracer {}", w))?;
            let share: &Fq = received_shares
                .get(w)
                .ok_or_else(|| format!("missing share from qualified tracer {}", w))?;

            pk_e = pk_e.add(&broadcast.pk);
            sk_e = sk_e.add(share);
        }

        Ok(TracerKeyShare {
            index: self.index,
            s: self.secret(),
            pk: self.broadcast.pk,
            sk_e,
            vk: Gt::base_mul(&sk_e),
            pk_e,
            qual: sorted_qual,
            threshold: self.threshold,
        })
    }
}

/// Step 7: verifies the proof of knowledge in a broadcast,
/// `R_w = g^{mu_w} * pk_w^{-h_w}`.
pub fn verify_broadcast(broadcast: &DkgBroadcast, threshold: usize) -> Result<(), String> {
    if broadcast.commitments.len() != threshold {
        return Err(format!(
            "tracer {} committed to {} coefficients, expected t_e = {}",
            broadcast.index,
            broadcast.commitments.len(),
            threshold
        ));
    }
    if broadcast.commitments[0] != broadcast.pk {
        return Err(format!(
            "tracer {} announced a pk_k that does not match its commitment A_k0",
            broadcast.index
        ));
    }
    if broadcast.pk.is_identity() {
        return Err(format!("tracer {} announced the identity as pk_k", broadcast.index));
    }

    let h: Fq = pok_challenge(broadcast.index, &broadcast.pk, &broadcast.nonce_commitment);
    let expected: Gt = Gt::base_mul(&broadcast.mu).add(&broadcast.pk.mul(&h.neg()));

    if expected != broadcast.nonce_commitment {
        return Err(format!(
            "proof of knowledge of tracer {} does not verify",
            broadcast.index
        ));
    }
    Ok(())
}

/// Step 9: verifies a received share against the dealer's Feldman
/// commitments, `g^{s_{wk}} = prod_l A_{wl}^{k^l}`.
pub fn verify_share(
    dealer: &DkgBroadcast,
    share: &Fq,
    receiver_index: usize,
) -> Result<(), String> {
    let expected: Gt = feldman_evaluate(&dealer.commitments, receiver_index);
    if Gt::base_mul(share) != expected {
        return Err(format!(
            "share from tracer {} to tracer {} is inconsistent with its commitments",
            dealer.index, receiver_index
        ));
    }
    Ok(())
}

/// Evaluates the committed polynomial in the exponent: `prod_l A_l^{x^l}`.
pub fn feldman_evaluate(commitments: &[Gt], x: usize) -> Gt {
    let x_scalar: Fq = Fq::from_u64(x as u64);
    let mut accumulator: Gt = Gt::identity();
    let mut power: Fq = Fq::one();
    for commitment in commitments.iter() {
        accumulator = accumulator.add(&commitment.mul(&power));
        power = power.mul(&x_scalar);
    }
    accumulator
}

/// Publicly recomputes the verification key of tracer `k` from the qualified
/// dealers' commitments: `vk_k = prod_{w in QUAL} prod_l A_{wl}^{k^l}`.
///
/// This lets any party check a partial decryption without trusting the
/// tracer's self-reported `vk_k`.
pub fn verification_key(
    qual: &[usize],
    broadcasts: &BTreeMap<usize, DkgBroadcast>,
    k: usize,
) -> Result<Gt, String> {
    let mut accumulator: Gt = Gt::identity();
    for w in qual.iter() {
        let broadcast: &DkgBroadcast = broadcasts
            .get(w)
            .ok_or_else(|| format!("missing broadcast from qualified tracer {}", w))?;
        accumulator = accumulator.add(&feldman_evaluate(&broadcast.commitments, k));
    }
    Ok(accumulator)
}

/// Runs the whole DKG locally, for `n_3` tracers modeled in a single
/// process. Used by the test suite and by any simulation that does not need
/// real inter-tracer networking.
pub fn run_dkg(threshold: usize, total: usize) -> Result<Vec<TracerKeyShare>, String> {
    let participants: Vec<DkgParticipant> = (1..=total)
        .map(|index| DkgParticipant::new(index, threshold, total))
        .collect::<Result<Vec<DkgParticipant>, String>>()?;

    let mut broadcasts: BTreeMap<usize, DkgBroadcast> = BTreeMap::new();
    for participant in participants.iter() {
        verify_broadcast(&participant.broadcast, threshold)?;
        broadcasts.insert(participant.index, participant.broadcast.clone());
    }

    let mut outputs: Vec<TracerKeyShare> = Vec::with_capacity(total);
    for participant in participants.iter() {
        let mut received: BTreeMap<usize, Fq> = BTreeMap::new();
        let mut qual: Vec<usize> = Vec::with_capacity(total);

        for dealer in participants.iter() {
            let share: Fq = dealer.share_for(participant.index);
            if verify_share(&dealer.broadcast, &share, participant.index).is_ok() {
                received.insert(dealer.index, share);
                qual.push(dealer.index);
            }
        }

        outputs.push(participant.finalize(&qual, &broadcasts, &received)?);
    }

    Ok(outputs)
}

// ---------------------------------------------------------------------------
// Threshold decryption (Figures `chaum-pederson`, `elgamal-decryption`).
// ---------------------------------------------------------------------------

/// A Chaum-Pedersen proof that `vk = g^{sk}` and `vk' = h^{sk}` share the
/// same exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaumPedersenProof {
    /// `com_1 = g^psi`.
    pub com1: Gt,
    /// `com_2 = h^psi`.
    pub com2: Gt,
    /// `theta = psi + ch * sk`.
    pub theta: Fq,
}

/// `ch = H(g || h || vk || vk' || com_1 || com_2)`.
fn chaum_pedersen_challenge(h: &Gt, vk: &Gt, vk_prime: &Gt, com1: &Gt, com2: &Gt) -> Fq {
    let mut transcript = Transcript::new(TAG_CHAUM_PEDERSEN);
    transcript.absorb_point(&Gt::generator());
    transcript.absorb_point(h);
    transcript.absorb_point(vk);
    transcript.absorb_point(vk_prime);
    transcript.absorb_point(com1);
    transcript.absorb_point(com2);
    transcript.finalize_scalar()
}

impl ChaumPedersenProof {
    /// `ChaumPedersonProof(g, h, vk, vk', sk)`.
    pub fn prove(h: &Gt, vk: &Gt, vk_prime: &Gt, sk: &Fq) -> ChaumPedersenProof {
        let psi: Fq = Fq::random();
        let com1: Gt = Gt::base_mul(&psi);
        let com2: Gt = h.mul(&psi);
        let ch: Fq = chaum_pedersen_challenge(h, vk, vk_prime, &com1, &com2);
        ChaumPedersenProof {
            com1,
            com2,
            theta: psi.add(&ch.mul(sk)),
        }
    }

    /// `ChaumPedersonVerify(g, h, vk, vk', com_1, com_2, theta)`.
    pub fn verify(&self, h: &Gt, vk: &Gt, vk_prime: &Gt) -> bool {
        let ch: Fq = chaum_pedersen_challenge(h, vk, vk_prime, &self.com1, &self.com2);
        let first: bool = Gt::base_mul(&self.theta) == self.com1.add(&vk.mul(&ch));
        let second: bool = h.mul(&self.theta) == self.com2.add(&vk_prime.mul(&ch));
        first && second
    }
}

/// The ciphertext components the tracers jointly decrypt: `ct = (c0, c1)`
/// (the aggregate response `z'`) together with every signer's attendance-bit
/// ciphertext `v_i = (v_{0_i}, v_{1_i})`. TAPS_TT has a single combiner, so
/// unlike the multi-combiner protocol there is nothing to aggregate here -
/// these are exactly the values the combiner published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionInput {
    pub c0: Gt,
    pub c1: Gt,
    /// `v0[i]`, `v1[i]` for every signer `i`.
    pub v0: Vec<Gt>,
    pub v1: Vec<Gt>,
}

impl DecryptionInput {
    /// Builds the decryption input from the `secp256k1::PublicKey` values the
    /// rest of the protocol works with.
    pub fn from_public_keys(
        c0: &PublicKey,
        c1: &PublicKey,
        v0: &[PublicKey],
        v1: &[PublicKey],
    ) -> Self {
        DecryptionInput {
            c0: Gt::from_public_key(c0),
            c1: Gt::from_public_key(c1),
            v0: v0.iter().map(Gt::from_public_key).collect(),
            v1: v1.iter().map(Gt::from_public_key).collect(),
        }
    }
}

/// The partial decryption tracer `k` publishes, with its proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// 1-based index `k` of the tracer.
    pub tracer_index: usize,
    /// Verification key `vk_k = g^{sk_{e_k}}`.
    pub vk: Gt,
    /// `c'_k = c_0^{sk_{e_k}}`.
    pub c_prime: Gt,
    /// Proof that `c'_k` uses the same exponent as `vk_k`.
    pub c_proof: ChaumPedersenProof,
    /// `v'_{0_{ki}} = v_{0_i}^{sk_{e_k}}` for every signer.
    pub v_prime: Vec<Gt>,
    /// Proofs for each `v'_{0_{ki}}`.
    pub v_proofs: Vec<ChaumPedersenProof>,
}

/// Steps 2 and 4 to 6 of Figure `elgamal-decryption`: tracer `k` produces its
/// partial decryptions and the accompanying Chaum-Pedersen proofs.
pub fn partial_decrypt(share: &TracerKeyShare, input: &DecryptionInput) -> PartialDecryption {
    let c_prime: Gt = input.c0.mul(&share.sk_e);
    let c_proof: ChaumPedersenProof =
        ChaumPedersenProof::prove(&input.c0, &share.vk, &c_prime, &share.sk_e);

    let mut v_prime: Vec<Gt> = Vec::with_capacity(input.v0.len());
    let mut v_proofs: Vec<ChaumPedersenProof> = Vec::with_capacity(input.v0.len());
    for v0_i in input.v0.iter() {
        let partial: Gt = v0_i.mul(&share.sk_e);
        v_proofs.push(ChaumPedersenProof::prove(
            v0_i,
            &share.vk,
            &partial,
            &share.sk_e,
        ));
        v_prime.push(partial);
    }

    PartialDecryption {
        tracer_index: share.index,
        vk: share.vk,
        c_prime,
        c_proof,
        v_prime,
        v_proofs,
    }
}

/// Steps 9 and 10: checks every proof of one partial decryption.
///
/// `expected_vk` should come from the DKG commitments (see
/// [`verification_key`]) rather than from the partial decryption itself, so
/// a malicious tracer cannot substitute a key it controls.
pub fn verify_partial_decryption(
    partial: &PartialDecryption,
    input: &DecryptionInput,
    expected_vk: &Gt,
) -> Result<(), usize> {
    if partial.vk != *expected_vk {
        return Err(partial.tracer_index);
    }
    if partial.v_prime.len() != input.v0.len() || partial.v_proofs.len() != input.v0.len() {
        return Err(partial.tracer_index);
    }
    if !partial.c_proof.verify(&input.c0, &partial.vk, &partial.c_prime) {
        return Err(partial.tracer_index);
    }
    for i in 0..input.v0.len() {
        if !partial.v_proofs[i].verify(&input.v0[i], &partial.vk, &partial.v_prime[i]) {
            return Err(partial.tracer_index);
        }
    }
    Ok(())
}

/// Step 11: `lambda^I_w = prod_{l in I \ {w}} l / (l - w)`.
pub fn lagrange_coefficient(indices: &[usize], w: usize) -> Result<Fq, String> {
    let w_scalar: Fq = Fq::from_u64(w as u64);
    let mut coefficient: Fq = Fq::one();

    for l in indices.iter() {
        if *l == w {
            continue;
        }
        let l_scalar: Fq = Fq::from_u64(*l as u64);
        let denominator: Fq = l_scalar.sub(&w_scalar);
        let factor: Fq = l_scalar
            .div(&denominator)
            .ok_or_else(|| format!("duplicate tracer index {} in the decryption set", l))?;
        coefficient = coefficient.mul(&factor);
    }

    Ok(coefficient)
}

/// Steps 12 and 13: recombines `t_e` verified partial decryptions into
/// `g^{z'}` and `{g^{b_i}}`.
pub fn combine_partial_decryptions(
    input: &DecryptionInput,
    partials: &[PartialDecryption],
    threshold: usize,
) -> Result<(Gt, Vec<Gt>), String> {
    if partials.len() < threshold {
        return Err(format!(
            "only {} partial decryptions supplied, the threshold is t_e = {}",
            partials.len(),
            threshold
        ));
    }

    // Use exactly t_e partials so the Lagrange interpolation is well defined.
    let selected: &[PartialDecryption] = &partials[..threshold];
    let indices: Vec<usize> = selected
        .iter()
        .map(|partial| partial.tracer_index)
        .collect();

    let mut c_accumulator: Gt = Gt::identity();
    let mut v_accumulator: Vec<Gt> = vec![Gt::identity(); input.v0.len()];

    for partial in selected.iter() {
        let lambda: Fq = lagrange_coefficient(&indices, partial.tracer_index)?;
        c_accumulator = c_accumulator.add(&partial.c_prime.mul(&lambda));
        for i in 0..input.v0.len() {
            v_accumulator[i] = v_accumulator[i].add(&partial.v_prime[i].mul(&lambda));
        }
    }

    let g_z_prime: Gt = input.c1.sub(&c_accumulator);
    let g_bits: Vec<Gt> = (0..input.v0.len())
        .map(|i| input.v1[i].sub(&v_accumulator[i]))
        .collect();

    Ok((g_z_prime, g_bits))
}

/// Convenience wrapper running `ElGamalDecryption` for a set of cooperating
/// tracers holding their own shares (used by tests and single-process
/// simulations).
pub fn threshold_decrypt(
    input: &DecryptionInput,
    shares: &[TracerKeyShare],
    verification_keys: &BTreeMap<usize, Gt>,
) -> Result<(Gt, Vec<Gt>), String> {
    if shares.is_empty() {
        return Err("no tracer shares supplied".to_string());
    }
    let threshold: usize = shares[0].threshold;

    let mut partials: Vec<PartialDecryption> = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        let partial: PartialDecryption = partial_decrypt(share, input);
        let expected_vk: &Gt = verification_keys
            .get(&share.index)
            .ok_or_else(|| format!("no verification key published for tracer {}", share.index))?;
        verify_partial_decryption(&partial, input, expected_vk)
            .map_err(|blamed| format!("partial decryption of tracer {} is invalid", blamed))?;
        partials.push(partial);
    }

    combine_partial_decryptions(input, &partials, threshold)
}

/// Decodes a decrypted `g^{b_i}` value: `1_G` means `0`, `g` means `1`, and
/// anything else means the signer must be blamed (step 1 of Figure `trace`).
pub fn decode_bit(g_bit: &Gt, signer_index: usize) -> Result<u8, String> {
    if g_bit.is_identity() {
        Ok(0)
    } else if *g_bit == Gt::generator() {
        Ok(1)
    } else {
        Err(format!(
            "Blame: signer {} decrypted to a value outside {{1, g}}",
            signer_index
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qual_and_vks(shares: &[TracerKeyShare]) -> BTreeMap<usize, Gt> {
        shares.iter().map(|s| (s.index, s.vk)).collect()
    }

    #[test]
    fn dkg_produces_a_consistent_group_key_for_one_tracer() {
        // n_3 = 1, t_e = floor(2*1/3) + 1 = 1.
        let shares = run_dkg(1, 1).expect("DKG must succeed for a single tracer");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].pk_e, shares[0].pk);
        assert_eq!(shares[0].vk, Gt::base_mul(&shares[0].sk_e));
    }

    #[test]
    fn dkg_produces_a_consistent_group_key_for_five_tracers() {
        // n_3 = 5, t_e = floor(2*5/3) + 1 = 4.
        let shares = run_dkg(4, 5).expect("DKG must succeed for five tracers");
        assert_eq!(shares.len(), 5);
        let pk_e = shares[0].pk_e;
        for share in shares.iter() {
            assert_eq!(share.pk_e, pk_e, "every tracer must agree on pk_e");
        }
    }

    #[test]
    fn threshold_decryption_recovers_the_plaintext() {
        let shares = run_dkg(4, 5).unwrap();
        let vks = qual_and_vks(&shares);

        let z = Fq::from_u64(42);
        let rho = Fq::random();
        let pk_e = shares[0].pk_e;

        let c0 = Gt::base_mul(&rho);
        let c1 = Gt::base_mul(&z).add(&pk_e.mul(&rho));

        let input = DecryptionInput {
            c0,
            c1,
            v0: vec![],
            v1: vec![],
        };

        // Any t_e = 4 of the 5 tracers should reconstruct the plaintext.
        let (g_z, _) = threshold_decrypt(&input, &shares[1..5], &vks).unwrap();
        assert_eq!(g_z, Gt::base_mul(&z));

        let (g_z_other_subset, _) = threshold_decrypt(&input, &shares[0..4], &vks).unwrap();
        assert_eq!(g_z_other_subset, Gt::base_mul(&z));
    }

    #[test]
    fn threshold_decryption_recovers_attendance_bits() {
        let shares = run_dkg(1, 1).unwrap();
        let vks = qual_and_vks(&shares);
        let pk_e = shares[0].pk_e;

        let gamma0 = Fq::random();
        let gamma1 = Fq::random();
        let v0 = vec![Gt::base_mul(&gamma0), Gt::base_mul(&gamma1)];
        let v1 = vec![
            Gt::identity().add(&pk_e.mul(&gamma0)), // bit = 0
            Gt::generator().add(&pk_e.mul(&gamma1)), // bit = 1
        ];

        let rho = Fq::random();
        let z = Fq::zero();
        let input = DecryptionInput {
            c0: Gt::base_mul(&rho),
            c1: Gt::base_mul(&z).add(&pk_e.mul(&rho)),
            v0,
            v1,
        };

        let (_, g_bits) = threshold_decrypt(&input, &shares, &vks).unwrap();
        assert_eq!(decode_bit(&g_bits[0], 0).unwrap(), 0);
        assert_eq!(decode_bit(&g_bits[1], 1).unwrap(), 1);
    }

    #[test]
    fn tampered_partial_decryption_is_rejected() {
        let shares = run_dkg(4, 5).unwrap();
        let vks = qual_and_vks(&shares);
        let pk_e = shares[0].pk_e;

        let rho = Fq::random();
        let z = Fq::from_u64(7);
        let input = DecryptionInput {
            c0: Gt::base_mul(&rho),
            c1: Gt::base_mul(&z).add(&pk_e.mul(&rho)),
            v0: vec![],
            v1: vec![],
        };

        let mut partial = partial_decrypt(&shares[0], &input);
        // Tamper with the published c_prime without redoing the proof.
        partial.c_prime = partial.c_prime.add(&Gt::generator());

        let expected_vk = vks.get(&shares[0].index).unwrap();
        assert!(verify_partial_decryption(&partial, &input, expected_vk).is_err());
    }
}

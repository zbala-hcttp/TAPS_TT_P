//! End-to-end checks of the rayon-parallel tracing step.
//!
//! For several `(n, t, j, t_e)` configurations a full TAPS_TT signature is
//! produced for a known signing quorum `C`, the accountability proof and the
//! combiner signature are verified, and the `j` tracers then run ShareDec,
//! the batched share verification and Rec. The traced quorum must be exactly
//! `C`, and the result must not depend on the size of the rayon thread pool.

use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::ThreadPoolBuilder;
use secp256k1::{PublicKey, Scalar};
use taps_tt_p::protocol::dkg::{
    self, ChaumPedersenProof, DecryptionInput, PartialDecryption, TracerKeyShare,
};
use taps_tt_p::protocol::group::Gt;
use taps_tt_p::protocol::taps_tt_p::*;

/// Tracer reconstruction threshold used by the simulation: `floor(2j/3)+1`.
fn tracer_threshold(j: usize) -> usize {
    (2 * j) / 3 + 1
}

/// Signer threshold used by the simulation: `floor(n/2)+1`.
fn signer_threshold(n: usize) -> usize {
    n / 2 + 1
}

/// Everything the tracers receive from the combiner, plus the ground truth.
struct SignedRun {
    pk: PK,
    message: Vec<u8>,
    t_cipher: ElGamalCiphertext,
    v0: Vec<PublicKey>,
    v1: Vec<PublicKey>,
    proofs: Proofs,
    sigma: Sigma,
    /// The quorum `C` that actually signed, as 0-based signer indices.
    expected_quorum: Vec<usize>,
    shares: Vec<TracerKeyShare>,
}

fn scalar_from_usize(value: usize) -> Scalar {
    let mut bytes: [u8; 32] = [0u8; 32];
    bytes[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("small integer is a valid scalar")
}

/// Runs the tracers' DKG, key generation, signing and combining for `n`
/// signers of which a random quorum of exactly `t = floor(n/2)+1` signs (as
/// `Quorum::choose` does: `T` encrypts `t` and the proof shows
/// `sum b_i = t`), with `j` tracers.
fn sign_with_random_quorum(n: usize, j: usize) -> SignedRun {
    let t: usize = signer_threshold(n);
    let te: usize = tracer_threshold(j);
    let quorum_size: usize = t;

    // Tracer DKG -> pk_e.
    let shares: Vec<TracerKeyShare> = dkg::run_dkg(te, j).expect("DKG succeeds");
    let pk_e: PublicKey = shares[0].pk_e_as_public_key();

    // Signers, combiner and registry.
    let signers: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();
    let kp_cs: KeyPair = KeyPair::create();
    let pk: PK = PK::set(&signers, &kp_cs, pk_e);

    // Pick the signing quorum C.
    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut thread_rng());
    let mut bits: Vec<u8> = vec![0u8; n];
    for &i in indices.iter().take(quorum_size) {
        bits[i] = 1;
    }
    let expected_quorum: Vec<usize> = (0..n).filter(|&i| bits[i] == 1).collect();
    let quo: Quorum = Quorum::set(&pk, &bits);

    // Round 1: commitments and aggregate nonce.
    let commits: Vec<Commit> = (0..n).map(|_| Commit::commit()).collect();
    let commitments: Vec<Commitment> = commits.iter().map(Commitment::set).collect();
    let r_agg: PublicKey = Commitment::aggregate(&commitments, &quo).expect("non-empty quorum");

    // Encrypted threshold T and challenge c.
    let psi: Secret = Secret::create();
    let t_cipher: ElGamalCiphertext =
        ElGamalCiphertext::encrypt_value(&psi, &scalar_from_usize(t));
    let message: Vec<u8> = b"parallel tracing test".to_vec();
    let c: Scalar = compute_challenge_c(&pk, &t_cipher, &r_agg, &message);

    // Round 2: partial signatures and aggregation.
    let sign_shares: Vec<Sign> = signers
        .iter()
        .zip(commits.iter())
        .map(|(kp, comm)| Sign::sign(comm, kp, &c))
        .collect();
    let z: Sign = Sign::aggregate(&sign_shares, &quo);

    // Combiner: encrypt z and the bits, prove, sign.
    let rho: Secret = Secret::create();
    let ct: ElGamalCiphertext = ElGamalCiphertext::encrypt(&rho, &z, &pk);
    let (gammas, ciphertexts): (Vec<Secret>, Vec<ElGamalCiphertext>) =
        encrypt_bits_threshold(&quo, &pk_e);
    let v0: Vec<PublicKey> = ciphertexts.iter().map(|cipher| cipher.c0).collect();
    let v1: Vec<PublicKey> = ciphertexts.iter().map(|cipher| cipher.c1).collect();

    let (alpha, beta, proofs, blinds): (Scalar, Scalar, Proofs, Blinds) = {
        let stmt: Statement = Statement {
            pk: &pk,
            T: &t_cipher,
            R: &r_agg,
            m: &message,
            ct: &ct,
            v0: &v0,
            v: &v1,
        };
        let alpha: Scalar = stmt.alpha(&c);
        let blinds: Blinds = Blinds::set(n);
        let proofs: Proofs = Proofs::compute_proofs(&blinds, &pk, &pk_e, &v1, &c, &alpha);
        let beta: Scalar = stmt.beta(&alpha, &proofs);
        (alpha, beta, proofs, blinds)
    };
    let phis: Phis = Phis::set(&alpha, &gammas, &quo);
    let witnesses: Witnesses = Witnesses::set(z, rho, &gammas, psi, &quo, &phis);
    let hats: Hats = Hats::set(&beta, &witnesses, &blinds);
    let sigma: Sigma = Sigma::sign(&kp_cs, &message, &r_agg, &ct, Pi { beta, hats });

    SignedRun {
        pk,
        message,
        t_cipher,
        v0,
        v1,
        proofs,
        sigma,
        expected_quorum,
        shares,
    }
}

impl SignedRun {
    fn statement(&self) -> Statement<'_> {
        Statement {
            pk: &self.pk,
            T: &self.t_cipher,
            R: &self.sigma.R,
            m: &self.message,
            ct: &self.sigma.ct,
            v0: &self.v0,
            v: &self.v1,
        }
    }

    fn decryption_input(&self) -> DecryptionInput {
        DecryptionInput::from_public_keys(&self.sigma.ct.c0, &self.sigma.ct.c1, &self.v0, &self.v1)
    }

    /// Verification of the combiner's signature and accountability proof.
    fn verify(&self) -> bool {
        let sigma_ok: bool = Sigma::verify(&self.pk, &self.message, &self.sigma).unwrap_or(false);
        let proof_ok: bool =
            Proofs::verify(&self.proofs, &self.sigma, &self.statement()).unwrap_or(false);
        sigma_ok && proof_ok
    }

    /// The tracers' side: ShareDec for every tracer, batched verification of
    /// every share and proof, Rec from the first `t_e` valid partials, and
    /// the final `g^z` consistency check. Returns the traced quorum.
    fn trace(&self) -> Result<Vec<usize>, String> {
        let input: DecryptionInput = self.decryption_input();
        let te: usize = self.shares[0].threshold;

        let partials: Vec<PartialDecryption> = self
            .shares
            .iter()
            .map(|share| dkg::partial_decrypt(share, &input))
            .collect();
        let expected_vks: Vec<Gt> = self.shares.iter().map(|share| share.vk).collect();

        let verdicts: Vec<Result<(), usize>> =
            dkg::verify_partial_decryptions(&partials, &input, &expected_vks);
        let valid: Vec<PartialDecryption> = partials
            .into_iter()
            .zip(verdicts)
            .filter(|(_, verdict)| verdict.is_ok())
            .map(|(partial, _)| partial)
            .collect();

        let (g_z, g_bits): (Gt, Vec<Gt>) = dkg::combine_partial_decryptions(&input, &valid, te)?;
        let bits: Vec<u8> = g_bits
            .iter()
            .enumerate()
            .map(|(i, g_bit)| dkg::decode_bit(g_bit, i))
            .collect::<Result<Vec<u8>, String>>()?;

        let quo: Quorum = Quorum::set(&self.pk, &bits);
        let c: Scalar = self.statement().c();
        let g_z_expected: PublicKey = schnorr_signature(&self.sigma.R, &quo, &c);
        if g_z != Gt::from_public_key(&g_z_expected) {
            return Err("decrypted g^z does not match the traced quorum".to_string());
        }

        Ok((0..bits.len()).filter(|&i| bits[i] == 1).collect())
    }
}

/// Sequential reference for the batched verification: every proof of one
/// partial, checked one after another exactly as the baseline does.
fn verify_sequential_reference(
    partial: &PartialDecryption,
    input: &DecryptionInput,
    expected_vk: &Gt,
) -> bool {
    if partial.vk != *expected_vk || partial.v_prime.len() != input.v0.len() {
        return false;
    }
    if !partial.c_proof.verify(&input.c0, &partial.vk, &partial.c_prime) {
        return false;
    }
    (0..input.v0.len()).all(|i| {
        let proof: &ChaumPedersenProof = &partial.v_proofs[i];
        proof.verify(&input.v0[i], &partial.vk, &partial.v_prime[i])
    })
}

/// `(n, j)`; `t = floor(n/2)+1`, `t_e = floor(2j/3)+1`.
const CONFIGURATIONS: [(usize, usize); 9] = [
    (1, 1),
    (3, 1),
    (5, 2),
    (5, 3),
    (10, 1),
    (10, 5),
    (16, 7),
    (25, 5),
    (50, 4),
];

#[test]
fn parallel_tracing_returns_the_signing_quorum() {
    for &(n, j) in CONFIGURATIONS.iter() {
        let run: SignedRun = sign_with_random_quorum(n, j);
        assert!(run.verify(), "valid signature rejected for n={} j={}", n, j);
        let traced: Vec<usize> = run.trace().expect("tracing succeeds");
        assert_eq!(
            traced,
            run.expected_quorum,
            "traced quorum differs for n={} t={} j={} t_e={}",
            n,
            signer_threshold(n),
            j,
            tracer_threshold(j)
        );
    }
}

#[test]
fn tracing_result_is_independent_of_the_thread_count() {
    let run: SignedRun = sign_with_random_quorum(10, 5);
    for threads in [1usize, 2, 4, 8] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool");
        let (verified, traced): (bool, Result<Vec<usize>, String>) =
            pool.install(|| (run.verify(), run.trace()));
        assert!(verified, "verification failed with {} thread(s)", threads);
        assert_eq!(
            traced.expect("tracing succeeds"),
            run.expected_quorum,
            "traced quorum differs with {} thread(s)",
            threads
        );
    }
}

#[test]
fn batched_verification_matches_the_sequential_reference() {
    // j = 7, t_e = 5: two tampered partials still leave five valid ones.
    let run: SignedRun = sign_with_random_quorum(8, 7);
    let input: DecryptionInput = run.decryption_input();
    let mut partials: Vec<PartialDecryption> = run
        .shares
        .iter()
        .map(|share| dkg::partial_decrypt(share, &input))
        .collect();
    let expected_vks: Vec<Gt> = run.shares.iter().map(|share| share.vk).collect();

    // Tamper with one bit share of tracer 2 and the c-share of tracer 4.
    partials[1].v_prime[3] = partials[1].v_prime[3].add(&Gt::generator());
    partials[3].c_prime = partials[3].c_prime.add(&Gt::generator());

    let batched: Vec<Result<(), usize>> =
        dkg::verify_partial_decryptions(&partials, &input, &expected_vks);
    for (k, partial) in partials.iter().enumerate() {
        let reference: bool = verify_sequential_reference(partial, &input, &expected_vks[k]);
        assert_eq!(batched[k].is_ok(), reference, "verdict differs for tracer {}", k + 1);
        // The single-partial API must agree with the batch.
        assert_eq!(
            dkg::verify_partial_decryption(partial, &input, &expected_vks[k]).is_ok(),
            reference
        );
    }
    assert_eq!(batched[1], Err(partials[1].tracer_index));
    assert_eq!(batched[3], Err(partials[3].tracer_index));
    assert!(batched[0].is_ok() && batched[2].is_ok());

    // t_e = 5 valid partials remain, so Rec still recovers C.
    let valid: Vec<PartialDecryption> = partials
        .into_iter()
        .zip(batched)
        .filter(|(_, verdict)| verdict.is_ok())
        .map(|(partial, _)| partial)
        .collect();
    let (_, g_bits): (Gt, Vec<Gt>) =
        dkg::combine_partial_decryptions(&input, &valid, tracer_threshold(7)).expect("rec");
    let traced: Vec<usize> = (0..g_bits.len())
        .filter(|&i| dkg::decode_bit(&g_bits[i], i).expect("bit") == 1)
        .collect();
    assert_eq!(traced, run.expected_quorum);
}

#[test]
fn tampered_accountability_proof_is_rejected() {
    let mut run: SignedRun = sign_with_random_quorum(6, 3);
    assert!(run.verify());
    // Shift one per-bit commitment by g.
    let g: PublicKey = Gt::generator().to_public_key().expect("g");
    run.proofs.S4bi[2] = run.proofs.S4bi[2].combine(&g).expect("point addition");
    assert!(Proofs::verify(&run.proofs, &run.sigma, &run.statement()).is_err());
}

#[test]
fn tampered_hat_is_rejected_by_the_parallel_checks() {
    let mut run: SignedRun = sign_with_random_quorum(6, 3);
    // Changing a response leaves beta intact, so the failure must come from
    // the (parallel) S1 / S4bi / S4c equations themselves.
    run.sigma.pi.hats.b_hat[1] = Scalar::ONE;
    assert!(Proofs::verify(&run.proofs, &run.sigma, &run.statement()).is_err());
}

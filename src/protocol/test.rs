use super::taps_tt_p::*;
use super::dkg::{self, DecryptionInput, TracerKeyShare};
use super::group::Gt;

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::BTreeMap;

#[test]
fn test_keypair_methods() {
    let secp = Secp256k1::new();

    let kp1 = KeyPair::create();
    let kp2 = KeyPair::create();

    assert_ne!(kp1.pk, kp2.pk, "Keys should be random and distinct");

    let secret_bytes = [1u8; 32]; // [1, 1, 1, ... 1]

    // Create KeyPair from these bytes
    let kp_reconstructed =
        KeyPair::from_secret(&secret_bytes).expect("Should create from valid bytes");

    // Manually calculate what the Public Key SHOULD be
    let sk_manual = SecretKey::from_byte_array(secret_bytes).unwrap();
    let pk_manual = PublicKey::from_secret_key(&secp, &sk_manual);

    // Verify the wrapper produced the correct Public Key
    assert_eq!(
        kp_reconstructed.pk, pk_manual,
        "from_secret did not derive the correct Public Key"
    );

    // 3. Test public_key() Accessor
    assert_eq!(
        kp_reconstructed.pk, kp_reconstructed.pk,
        "Accessor should return the internal pk"
    );

    println!("KeyPair wrapper verified successfully!");
}

#[test]
fn test_quorum_choose() {
    let n = 10;
    let t = 6;

    // 1. Setup Dummy Signers
    let signers: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();

    // 2. Run the Function
    let quorum = Quorum::choose(n, t, &signers);

    // 3. Verify: Length is correct
    assert_eq!(
        quorum.participants.len(),
        n,
        "Quorum vector must have size n"
    );

    // 4. Verify: Signer Public Keys match the input order
    for (i, (pk, _)) in quorum.participants.iter().enumerate() {
        assert_eq!(*pk, signers[i].pk, "Signer order must be preserved");
    }

    // 5. Verify: Exactly 't' participants are selected (bit = 1)
    let selected_count = quorum
        .participants
        .iter()
        .filter(|(_, bit)| *bit == 1)
        .count();

    assert_eq!(selected_count, t, "Exactly t signers should have bit=1");

    // 6. Verify: Exactly 'n-t' participants are excluded (bit = 0)
    let excluded_count = quorum
        .participants
        .iter()
        .filter(|(_, bit)| *bit == 0)
        .count();

    assert_eq!(
        excluded_count,
        n - t,
        "Exactly n-t signers should have bit=0"
    );
}

#[test]
fn test_commit_generates_valid_nonce() {
    let comm = Commit::commit();

    let r_bytes = comm.nonce.sk.secret_bytes();
    let is_zero = r_bytes.iter().all(|&b| b == 0);

    assert!(
        !is_zero,
        "Commitment should generate a non-zero secret nonce 'r'"
    );
}

#[test]
fn test_sign_algebraic_verification() {
    let secp = Secp256k1::new();

    let identity_keys = KeyPair::create();
    let P = identity_keys.pk;

    // Create a Commitment (r, R)
    let comm = Commit::commit();
    let R = comm.nonce.pk;

    let mut buf = [0u8; 32];
    buf[0] = 1;
    buf[31] = 1;
    let c = Scalar::from_be_bytes(buf).unwrap();

    let z_scalar = Sign::sign(&comm, &identity_keys, &c);

    let z_sk = SecretKey::from_byte_array(z_scalar.z.to_be_bytes()).unwrap();
    let lhs = PublicKey::from_secret_key(&secp, &z_sk);

    let mut P_times_c = P;
    P_times_c = P_times_c.mul_tweak(&secp, &c).expect("Tweak failed");

    let rhs = R.combine(&P_times_c).expect("Combination failed");

    assert_eq!(lhs, rhs, "Equation failed: g*z should equal R + P*c");
}

#[test]
fn test_aggregate_scalars_summation() {
    fn make_sign(val: u64) -> Sign {
        let mut bytes = [0u8; 32];
        let val_bytes = val.to_be_bytes();
        bytes[24..32].copy_from_slice(&val_bytes);
        Sign {
            z: Scalar::from_be_bytes(bytes).unwrap(),
        }
    }

    let shares = vec![make_sign(10), make_sign(20), make_sign(30)];

    let dummy_kp = KeyPair::create();
    let pk = dummy_kp.pk;

    let participants = vec![(pk, 1), (pk, 0), (pk, 1)];

    let quo = Quorum { participants };

    let result_sign = Sign::aggregate(&shares, &quo);

    let result_bytes = result_sign.z.to_be_bytes();
    let mut small_bytes = [0u8; 8];
    small_bytes.copy_from_slice(&result_bytes[24..32]);
    let result_val = u64::from_be_bytes(small_bytes);

    assert_eq!(result_val, 40, "Aggregation should be 10 + 30 = 40");
}

#[test]
fn test_aggregate_commitments() {
    let c1 = Commit::commit();
    let c2 = Commit::commit();
    let c3 = Commit::commit();
    let commitments = vec![
        Commitment::set(&c1),
        Commitment::set(&c2),
        Commitment::set(&c3),
    ];

    let dummy_kp = KeyPair::create();
    let dummy_pk = dummy_kp.pk;

    let participants = vec![(dummy_pk, 1), (dummy_pk, 0), (dummy_pk, 1)];
    let quo = Quorum { participants };

    let agg_result = Commitment::aggregate(&commitments, &quo).unwrap();

    let expected = commitments[0].R.combine(&commitments[2].R).unwrap();

    assert_eq!(
        agg_result, expected,
        "Commitment aggregation failed: Should be R1 + R3"
    );
}

#[test]
fn test_second_generator_is_deterministic() {
    let h1 = get_second_generator_h();
    let h2 = get_second_generator_h();

    assert_eq!(
        h1, h2,
        "The second generator H must be consistent/deterministic"
    );

    println!("Second Generator H: {:?}", h1);
}

#[test]
fn test_secret_create_randomness() {
    let s1 = Secret::create();
    let s2 = Secret::create();

    assert_ne!(
        s1.s, s2.s,
        "Secret::create() must produce unique random values"
    );

    let sk1 = SecretKey::from_byte_array(s1.s.to_be_bytes());
    assert!(sk1.is_ok(), "Generated scalar must be a valid SecretKey");

    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk1.unwrap());

    assert_eq!(pk.serialize().len(), 33);
}

#[test]
fn test_elgamal_encryption_correctness() {
    let secp = Secp256k1::new();

    let r_secret = Secret::create();
    let mut m_bytes = [0u8; 32];
    m_bytes[31] = 20;
    let m_secret = Sign {
        z: Scalar::from_be_bytes(m_bytes).unwrap(),
    };
    let kp = KeyPair::create();
    let pk = PK {
        pk_i: vec![kp.pk],
        pk_cs: kp.pk,
        pk_t: kp.pk,
    };

    let ciphertext = ElGamalCiphertext::encrypt(&r_secret, &m_secret, &pk);

    let r_sk = SecretKey::from_byte_array(r_secret.s.to_be_bytes()).unwrap();
    let expected_c0 = PublicKey::from_secret_key(&secp, &r_sk);

    assert_eq!(ciphertext.c0, expected_c0, "c0 must equal g^r");

    let m_sk = SecretKey::from_byte_array(m_secret.z.to_be_bytes()).unwrap();
    let g_m = PublicKey::from_secret_key(&secp, &m_sk);

    let p_r = kp
        .pk
        .mul_tweak(&secp, &r_secret.s)
        .expect("Failed to calculate P^r");

    let expected_c1 = g_m.combine(&p_r).expect("Failed to add points");

    assert_eq!(ciphertext.c1, expected_c1, "c1 must equal g^m + P^r");

    println!("Encryption logic verified successfully!");
}

#[test]
fn test_encrypt_bits_threshold_logic() {
    let secp = Secp256k1::new();
    let g = generator();

    // Two signers: #0 absent, #1 present. n_3 = 1 tracer (t_e = 1).
    let shares = dkg::run_dkg(1, 1).expect("DKG must succeed for a single tracer");
    let pk_e = shares[0].pk_e_as_public_key();

    let dummy_pk = KeyPair::create().pk;
    let quo = Quorum {
        participants: vec![(dummy_pk, 0), (dummy_pk, 1)],
    };

    let (gammas, ciphertexts) = encrypt_bits_threshold(&quo, &pk_e);
    assert_eq!(gammas.len(), 2);
    assert_eq!(ciphertexts.len(), 2);

    for (i, gamma) in gammas.iter().enumerate() {
        let gamma_sk = SecretKey::from_byte_array(gamma.s.to_be_bytes()).unwrap();
        let expected_v0 = PublicKey::from_secret_key(&secp, &gamma_sk);
        assert_eq!(ciphertexts[i].c0, expected_v0, "v0_i must be g^gamma_i");

        let shared = pk_e.mul_tweak(&secp, &gamma.s).unwrap();
        let expected_v1 = if i == 1 {
            g.combine(&shared).unwrap()
        } else {
            shared
        };
        assert_eq!(ciphertexts[i].c1, expected_v1);
    }

    // Every ciphertext must use its own fresh randomness.
    assert_ne!(ciphertexts[0].c0, ciphertexts[1].c0);
}

fn qual_and_vks(shares: &[TracerKeyShare]) -> BTreeMap<usize, Gt> {
    shares.iter().map(|s| (s.index, s.vk)).collect()
}

/// Runs the full encrypt -> threshold-decrypt cycle for `n_3` tracers with
/// reconstruction threshold `t_e`, and checks the recovered bits match the
/// quorum that was encrypted.
fn encrypt_decrypt_bits_cycle(n3: usize, te: usize) {
    let n = 5;
    let t = 3;

    let signer_keys: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();
    let quorum = Quorum::choose(n, t, &signer_keys);
    let original_bits: Vec<u8> = quorum.participants.iter().map(|(_, bit)| *bit).collect();

    let shares = dkg::run_dkg(te, n3).expect("DKG must succeed");
    let pk_e = shares[0].pk_e_as_public_key();

    let (_, ciphertexts) = encrypt_bits_threshold(&quorum, &pk_e);
    let v0: Vec<PublicKey> = ciphertexts.iter().map(|c| c.c0).collect();
    let v1: Vec<PublicKey> = ciphertexts.iter().map(|c| c.c1).collect();

    // Dummy z/rho so the (c0, c1) pair of the decryption input is well
    // formed; this test only exercises bit recovery. `z` must be non-zero,
    // since `SecretKey` cannot represent the scalar 0.
    let rho = Secret::create();
    let mut z_bytes = [0u8; 32];
    z_bytes[31] = 7;
    let z = Sign {
        z: Scalar::from_be_bytes(z_bytes).unwrap(),
    };
    let ct = {
        let pk = PK {
            pk_i: signer_keys.iter().map(|kp| kp.pk).collect(),
            pk_cs: KeyPair::create().pk,
            pk_t: pk_e,
        };
        ElGamalCiphertext::encrypt(&rho, &z, &pk)
    };

    let input = DecryptionInput::from_public_keys(&ct.c0, &ct.c1, &v0, &v1);
    let vks = qual_and_vks(&shares);

    let (_, g_bits) = dkg::threshold_decrypt(&input, &shares[..te], &vks)
        .expect("threshold decryption must succeed");

    let decrypted_bits: Vec<u8> = g_bits
        .iter()
        .enumerate()
        .map(|(i, g_bit)| dkg::decode_bit(g_bit, i).expect("bit decryption failed"))
        .collect();

    assert_eq!(
        original_bits, decrypted_bits,
        "Decrypted bits do not match original quorum bits! (n_3={}, t_e={})",
        n3, te
    );
}

#[test]
fn test_encrypt_decrypt_bits_cycle_one_tracer() {
    encrypt_decrypt_bits_cycle(1, 1);
}

#[test]
fn test_encrypt_decrypt_bits_cycle_five_tracers() {
    // t_e = floor(2*5/3) + 1 = 4.
    encrypt_decrypt_bits_cycle(5, 4);
}

#[test]
fn test_encrypt_value_two_generators() {
    let secp = Secp256k1::new();
    let r_secret = Secret::create();

    let mut t_bytes = [0u8; 32];
    t_bytes[31] = 20;
    let t_scalar = Scalar::from_be_bytes(t_bytes).unwrap();

    let cipher = ElGamalCiphertext::encrypt_value(&r_secret, &t_scalar);

    let r_sk = SecretKey::from_byte_array(r_secret.s.to_be_bytes()).unwrap();
    let expected_c0 = PublicKey::from_secret_key(&secp, &r_sk);
    assert_eq!(cipher.c0, expected_c0, "c0 must be r*G");

    let t_sk = SecretKey::from_byte_array(t_bytes).unwrap();
    let expected_g_t = PublicKey::from_secret_key(&secp, &t_sk);

    let h = get_second_generator_h();
    let expected_h_r = h.mul_tweak(&secp, &r_secret.s).unwrap();

    let expected_c1 = expected_g_t.combine(&expected_h_r).unwrap();

    assert_eq!(cipher.c1, expected_c1, "c1 must be t*G + r*H");
}

#[test]
fn test_elgamal_decryption_success() {
    let secp = Secp256k1::new();
    let r_secret = Secret::create();

    let mut m_bytes = [0u8; 32];
    m_bytes[31] = 15;
    let m_scalar = Scalar::from_be_bytes(m_bytes).unwrap();
    let m_secret = Sign { z: m_scalar };

    let kp = KeyPair::create();
    let pk = PK {
        pk_i: vec![kp.pk],
        pk_cs: kp.pk,
        pk_t: kp.pk,
    };

    let ciphertext = ElGamalCiphertext::encrypt(&r_secret, &m_secret, &pk);

    let decrypted_point = ElGamalCiphertext::decrypt(&ciphertext, &kp);

    let m_sk = SecretKey::from_byte_array(m_bytes).unwrap();
    let expected_point = PublicKey::from_secret_key(&secp, &m_sk);

    assert_eq!(
        decrypted_point, expected_point,
        "Decryption failed: Did not recover g^m"
    );

    println!("Decryption test passed! Recovered point matches original message.");
}

/// Helper: builds a syntactically valid (but not algebraically meaningful)
/// statement, for exercising the hashing / transcript logic in isolation.
#[allow(clippy::type_complexity)]
fn dummy_statement_parts(
    n: usize,
) -> (
    PK,
    ElGamalCiphertext,
    PublicKey,
    ElGamalCiphertext,
    Vec<PublicKey>,
    Vec<PublicKey>,
) {
    let signer_keys: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();
    let combiner_key = KeyPair::create();
    let pk_e = KeyPair::create().pk;
    let pk = PK::set(&signer_keys, &combiner_key, pk_e);

    let T = ElGamalCiphertext {
        c0: KeyPair::create().pk,
        c1: KeyPair::create().pk,
    };
    let R = KeyPair::create().pk;
    let ct = ElGamalCiphertext {
        c0: KeyPair::create().pk,
        c1: KeyPair::create().pk,
    };
    let v0: Vec<PublicKey> = (0..n).map(|_| KeyPair::create().pk).collect();
    let v: Vec<PublicKey> = (0..n).map(|_| KeyPair::create().pk).collect();

    (pk, T, R, ct, v0, v)
}

#[test]
fn test_challenge_derivation_is_deterministic_and_sensitive() {
    let n = 5;
    let (pk, T, R, ct, v0, v) = dummy_statement_parts(n);

    let message: &[u8] = b"This is a test message for the TAPS protocol";

    let stmt = Statement {
        pk: &pk,
        T: &T,
        R: &R,
        m: message,
        ct: &ct,
        v0: &v0,
        v: &v,
    };

    let c1 = stmt.c();
    let alpha1 = stmt.alpha(&c1);

    // A. Never zero (hash_to_scalar rejects zero and out-of-range digests).
    assert_ne!(c1, Scalar::ZERO, "c should not be zero");
    assert_ne!(alpha1, Scalar::ZERO, "alpha should not be zero");

    // B. Domain separation keeps the two challenges apart.
    assert_ne!(c1, alpha1, "c and alpha should differ");

    // C. Determinism: same input -> same output.
    assert_eq!(stmt.c(), c1, "Hashing must be deterministic");
    assert_eq!(stmt.alpha(&c1), alpha1);

    // D. Sensitivity: a different message must change c.
    let stmt_alt = Statement {
        m: b"This is a DIFFERENT message",
        ..stmt
    };
    assert_ne!(c1, stmt_alt.c(), "Changing the message must change 'c'");

    // E. Sensitivity: alpha must react to the encrypted bits, since it is the
    //    batching challenge for the "b_i is a bit" checks.
    let mut v_alt = v.clone();
    v_alt[0] = KeyPair::create().pk;
    let stmt_v = Statement { v: &v_alt, ..stmt };
    assert_ne!(
        alpha1,
        stmt_v.alpha(&c1),
        "alpha must be bound to the encrypted bits v_i"
    );
}

#[test]
fn test_beta_is_bound_to_proof_commitments() {
    let n = 2;
    let (pk, T, R, ct, v0, v) = dummy_statement_parts(n);
    let pk_e = KeyPair::create().pk;

    let stmt = Statement {
        pk: &pk,
        T: &T,
        R: &R,
        m: b"bind me",
        ct: &ct,
        v0: &v0,
        v: &v,
    };

    let c = stmt.c();
    let alpha = stmt.alpha(&c);

    let blinds = Blinds::set(n);
    let proofs = Proofs::compute_proofs(&blinds, &pk, &pk_e, &v, &c, &alpha);
    let beta = stmt.beta(&alpha, &proofs);

    assert_ne!(beta, Scalar::ZERO);
    assert_ne!(beta, alpha, "alpha and beta should differ");
    assert_eq!(stmt.beta(&alpha, &proofs), beta, "beta must be deterministic");

    // Perturbing any single commitment must change beta - otherwise the prover
    // could pick its responses first and solve for the commitments afterwards.
    let mut tampered = proofs.clone();
    tampered.S1 = KeyPair::create().pk;
    assert_ne!(beta, stmt.beta(&alpha, &tampered), "beta must bind S1");

    let mut tampered = proofs.clone();
    tampered.S4c = KeyPair::create().pk;
    assert_ne!(beta, stmt.beta(&alpha, &tampered), "beta must bind S4c");

    let mut tampered = proofs.clone();
    tampered.S4bi[0] = KeyPair::create().pk;
    assert_ne!(beta, stmt.beta(&alpha, &tampered), "beta must bind S4bi");

    let mut tampered = proofs.clone();
    tampered.S4ai[0] = KeyPair::create().pk;
    assert_ne!(beta, stmt.beta(&alpha, &tampered), "beta must bind S4ai");
}

#[test]
fn test_phis_start_index_is_one() {
    // 1. Setup
    // Gamma = 2 (same value reused for both signers here purely to keep the
    // expected numbers simple - Phis::set takes one gamma_i per signer).
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes[31] = 2;
    let gamma_scalar = Scalar::from_be_bytes(gamma_bytes).unwrap();
    let gamma = Secret { s: gamma_scalar };

    // Alpha = 3
    let mut alpha_bytes = [0u8; 32];
    alpha_bytes[31] = 3;
    let alpha = Scalar::from_be_bytes(alpha_bytes).unwrap();

    // Quorum: 2 people, both absent (bits = 0)
    let dummy_pk = KeyPair::create().pk;
    let quo = Quorum {
        participants: vec![(dummy_pk, 0), (dummy_pk, 0)],
    };

    // 2. Execute
    let gammas = vec![gamma.clone(), gamma];
    let phis = Phis::set(&alpha, &gammas, &quo);

    // 3. Verify Index 1 (First Item)
    // Expected: gamma * alpha^1 = 2 * 3 = 6
    let val1_bytes = phis.phis[0].s.to_be_bytes();
    let val1 = u64::from_be_bytes(val1_bytes[24..32].try_into().unwrap());

    assert_eq!(val1, 6, "First item should be gamma * alpha^1 (2 * 3)");

    // 4. Verify Index 2 (Second Item)
    // Expected: gamma * alpha^2 = 2 * 9 = 18
    let val2_bytes = phis.phis[1].s.to_be_bytes();
    let val2 = u64::from_be_bytes(val2_bytes[24..32].try_into().unwrap());

    assert_eq!(val2, 18, "Second item should be gamma * alpha^2 (2 * 9)");
}

#[test]
fn test_witnesses_extraction() {
    // 1. Setup Scalars
    let z = Sign {
        z: Scalar::from_be_bytes([1u8; 32]).unwrap(),
    };
    let rho = Secret {
        s: Scalar::from_be_bytes([2u8; 32]).unwrap(),
    };
    let gamma = Secret {
        s: Scalar::from_be_bytes([3u8; 32]).unwrap(),
    };
    let psi = Secret {
        s: Scalar::from_be_bytes([4u8; 32]).unwrap(),
    };

    // 2. Setup Quorum with mixed bits
    let dummy_pk = KeyPair::create().pk;
    let quo = Quorum {
        participants: vec![(dummy_pk, 1), (dummy_pk, 0), (dummy_pk, 1)],
    };

    // 3. Setup Phis (Must match quorum length)
    let phis = Phis {
        phis: vec![
            Secret {
                s: Scalar::from_be_bytes([10u8; 32]).unwrap(),
            },
            Secret {
                s: Scalar::from_be_bytes([11u8; 32]).unwrap(),
            },
            Secret {
                s: Scalar::from_be_bytes([12u8; 32]).unwrap(),
            },
        ],
    };

    // 4. Execute set
    let gamma_s = gamma.s;
    let gammas = vec![gamma.clone(), gamma.clone(), gamma];
    let wit = Witnesses::set(z, rho, &gammas, psi, &quo, &phis);

    // 5. Verify Extraction
    assert_eq!(
        wit.b_i,
        vec![1, 0, 1],
        "Bits b_i were not extracted correctly from Quorum"
    );

    assert_eq!(wit.phi_i.len(), 3);
    assert_eq!(
        wit.phi_i[0], phis.phis[0].s,
        "Scalars phi_i were not extracted correctly from Phis"
    );
    assert_eq!(wit.gamma_i.len(), 3);
    assert_eq!(wit.gamma_i[0], gamma_s);

    println!("Witnesses extracted successfully!");
}

#[test]
fn test_blinds_generation() {
    let n = 5;

    let blinds = Blinds::set(n);

    assert_eq!(
        blinds.k_b_i.len(),
        n,
        "Should have generated n secrets for b_i"
    );
    assert_eq!(
        blinds.k_phi_i.len(),
        n,
        "Should have generated n secrets for phi_i"
    );
    assert_eq!(
        blinds.k_gamma_i.len(),
        n,
        "Should have generated n secrets for gamma_i"
    );

    assert_ne!(
        blinds.k_z.s, blinds.k_rho.s,
        "k_z and k_rho should be distinct random values"
    );

    assert_ne!(
        blinds.k_b_i[0].s, blinds.k_phi_i[0].s,
        "Vectors should contain distinct secrets"
    );

    println!(
        "Blinds structure initialized correctly with {} participants.",
        n
    );
}

#[test]
fn test_hats_set_logic() {
    // Beta (Challenge) = 2
    let mut beta_bytes = [0u8; 32];
    beta_bytes[31] = 2;
    let beta = Scalar::from_be_bytes(beta_bytes).unwrap();

    // Witness z = 5
    let mut z_bytes = [0u8; 32];
    z_bytes[31] = 5;
    let z = Scalar::from_be_bytes(z_bytes).unwrap();

    // Blind k_z = 3
    let mut k_z_bytes = [0u8; 32];
    k_z_bytes[31] = 3;
    let k_z = Secret {
        s: Scalar::from_be_bytes(k_z_bytes).unwrap(),
    };

    let witt = Witnesses {
        z,
        rho: Scalar::ZERO,
        gamma_i: vec![Scalar::ZERO],
        psi: Scalar::ZERO,
        b_i: vec![1],
        phi_i: vec![Scalar::ZERO],
    };

    let mut k_b_bytes = [0u8; 32];
    k_b_bytes[31] = 20;
    let k_b_secret = Secret {
        s: Scalar::from_be_bytes(k_b_bytes).unwrap(),
    };

    let bli = Blinds {
        k_z,
        k_rho: Secret::create(),
        k_gamma_i: vec![Secret::create()],
        k_psi: Secret::create(),
        k_b_i: vec![k_b_secret],
        k_phi_i: vec![Secret::create()],
    };

    let hats = Hats::set(&beta, &witt, &bli);

    // Verification 1: z_hat = z * beta + k_z = 5*2+3 = 13
    let z_hat_val = hats.z_hat.to_be_bytes()[31];
    assert_eq!(
        z_hat_val, 13,
        "z_hat calculation failed: 5*2+3 should be 13"
    );

    // Verification 2: b_hat (for bit = 1) = 1*2+20 = 22
    let b_hat_val = hats.b_hat[0].to_be_bytes()[31];
    assert_eq!(
        b_hat_val, 22,
        "b_hat calculation failed: 1*2+20 should be 22"
    );

    assert_eq!(hats.gamma_hat.len(), 1);

    println!("Hats set function passed: Math is correct.");
}

#[test]
fn test_verify_s1_computation_multiple() {
    let secp = Secp256k1::new();

    let mut c_bytes = [0u8; 32];
    c_bytes[31] = 2;
    let c = Scalar::from_be_bytes(c_bytes).unwrap();

    let mut kz_bytes = [0u8; 32];
    kz_bytes[31] = 100;
    let k_z = Secret {
        s: Scalar::from_be_bytes(kz_bytes).unwrap(),
    };

    let make_scalar = |v: u8| -> Scalar {
        let mut b = [0u8; 32];
        b[31] = v;
        Scalar::from_be_bytes(b).unwrap()
    };

    let make_pk = |v: u8| -> PublicKey {
        let sk = SecretKey::from_byte_array(make_scalar(v).to_be_bytes()).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    };

    let pk_i = vec![make_pk(1), make_pk(2), make_pk(4)];

    let k_b_i = vec![
        Secret { s: make_scalar(5) },
        Secret { s: make_scalar(3) },
        Secret { s: make_scalar(2) },
    ];

    let s1 = Proofs::compute_s1(&k_z, &k_b_i, &pk_i, &c);

    // Calc: 100 - 2*(1*5 + 2*3 + 4*2) = 62
    let expected_sk = SecretKey::from_byte_array(make_scalar(62).to_be_bytes()).unwrap();
    let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);

    assert_eq!(s1, expected_pk, "S1 summation logic failed. Expected 62*G.");

    println!("S1 verified successfully with 3 participants!");
}

#[test]
fn test_verify_sa_computation() {
    let secp = Secp256k1::new();

    let mut r_bytes = [0u8; 32];
    r_bytes[31] = 5;
    let k_r = Secret {
        s: Scalar::from_be_bytes(r_bytes).unwrap(),
    };

    let sa = Proofs::compute_sa(&k_r);

    let expected_sk = SecretKey::from_byte_array(r_bytes).unwrap();
    let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);

    assert_eq!(sa, expected_pk, "Sa should be g^k_r");

    println!("Sa verification passed.");
}

#[test]
fn test_compute_s2b() {
    let secp = Secp256k1::new();

    let mut pkt_bytes = [0u8; 32];
    pkt_bytes[31] = 10;
    let pkt_sk = SecretKey::from_byte_array(pkt_bytes).unwrap();
    let pk_t = PublicKey::from_secret_key(&secp, &pkt_sk);

    let mut rho_bytes = [0u8; 32];
    rho_bytes[31] = 2;
    let k_rho = Secret {
        s: Scalar::from_be_bytes(rho_bytes).unwrap(),
    };

    let mut kz_bytes = [0u8; 32];
    kz_bytes[31] = 3;
    let k_z = Secret {
        s: Scalar::from_be_bytes(kz_bytes).unwrap(),
    };

    let s2b = Proofs::compute_s2b(&pk_t, &k_rho, &k_z);

    // Calculation: 10*2 + 3 = 23
    let mut expected_bytes = [0u8; 32];
    expected_bytes[31] = 23;
    let expected_sk = SecretKey::from_byte_array(expected_bytes).unwrap();
    let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);

    assert_eq!(s2b, expected_pk, "S2b computation incorrect. Expected 23*G");

    println!("S2b verified successfully.");
}

#[test]
fn test_compute_s3b() {
    let secp = Secp256k1::new();

    let mut kb1_bytes = [0u8; 32];
    kb1_bytes[31] = 2;
    let mut kb2_bytes = [0u8; 32];
    kb2_bytes[31] = 3;
    let k_b_i = vec![
        Secret {
            s: Scalar::from_be_bytes(kb1_bytes).unwrap(),
        },
        Secret {
            s: Scalar::from_be_bytes(kb2_bytes).unwrap(),
        },
    ];

    let mut psi_bytes = [0u8; 32];
    psi_bytes[31] = 10;
    let k_psi = Secret {
        s: Scalar::from_be_bytes(psi_bytes).unwrap(),
    };

    let mut h_scalar_bytes = [0u8; 32];
    h_scalar_bytes[31] = 2;
    let h_sk = SecretKey::from_byte_array(h_scalar_bytes).unwrap();
    let h = PublicKey::from_secret_key(&secp, &h_sk);

    let s3b = Proofs::compute_s3b(&k_b_i, &k_psi, &h);

    // Expected: (2+3)*G + 10*(2*G) = 5G + 20G = 25G
    let mut expected_bytes = [0u8; 32];
    expected_bytes[31] = 25;
    let expected_sk = SecretKey::from_byte_array(expected_bytes).unwrap();
    let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);

    assert_eq!(s3b, expected_pk, "S3b computation failed. Expected 25*G");

    println!("S3b verified successfully.");
}

#[test]
fn test_compute_s4bi_vector() {
    let secp = Secp256k1::new();

    // Secrets k_b_i: [2, 3]
    let k_b_vec = vec![
        Secret {
            s: {
                let mut b = [0u8; 32];
                b[31] = 2;
                Scalar::from_be_bytes(b).unwrap()
            },
        },
        Secret {
            s: {
                let mut b = [0u8; 32];
                b[31] = 3;
                Scalar::from_be_bytes(b).unwrap()
            },
        },
    ];

    // Per-signer secrets k_gamma_i: [10, 10] (same value, applied against the
    // single shared pk_e instead of per-signer h_i generators).
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes[31] = 10;
    let k_gamma_i = vec![
        Secret {
            s: Scalar::from_be_bytes(gamma_bytes).unwrap(),
        },
        Secret {
            s: Scalar::from_be_bytes(gamma_bytes).unwrap(),
        },
    ];

    // pk_e = 2*G
    let mut pk_e_bytes = [0u8; 32];
    pk_e_bytes[31] = 2;
    let pk_e_sk = SecretKey::from_byte_array(pk_e_bytes).unwrap();
    let pk_e = PublicKey::from_secret_key(&secp, &pk_e_sk);

    let s4bi_vec = Proofs::compute_s4bi(&k_b_vec, &k_gamma_i, &pk_e);

    // Expected[0]: g^2 * pk_e^10 = 2G + 20G = 22G
    let mut exp1_bytes = [0u8; 32];
    exp1_bytes[31] = 22;
    let exp1_sk = SecretKey::from_byte_array(exp1_bytes).unwrap();
    let exp1_pk = PublicKey::from_secret_key(&secp, &exp1_sk);
    assert_eq!(s4bi_vec[0], exp1_pk, "Index 0 failed: Expected 22G");

    // Expected[1]: g^3 * pk_e^10 = 3G + 20G = 23G
    let mut exp2_bytes = [0u8; 32];
    exp2_bytes[31] = 23;
    let exp2_sk = SecretKey::from_byte_array(exp2_bytes).unwrap();
    let exp2_pk = PublicKey::from_secret_key(&secp, &exp2_sk);
    assert_eq!(s4bi_vec[1], exp2_pk, "Index 1 failed: Expected 23G");

    println!("S4bi vector computation verified.");
}

#[test]
fn test_compute_s4c() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut b = [0u8; 32];
        let bytes = v.to_be_bytes();
        b[24..32].copy_from_slice(&bytes);
        Scalar::from_be_bytes(b).unwrap()
    };
    let pk = |v: u64| -> PublicKey {
        let sk = SecretKey::from_byte_array(s(v).to_be_bytes()).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    };
    let secret = |v: u64| -> Secret { Secret { s: s(v) } };

    let alpha = s(2);
    let v_vec = vec![pk(10), pk(10)];
    let pk_e = pk(5);
    let kb_vec = vec![secret(3), secret(3)];
    let kp_vec = vec![secret(2), secret(2)];

    let s4c = Proofs::compute_s4c(&v_vec, &alpha, &kb_vec, &pk_e, &kp_vec);

    // Expected 200 * G (unchanged: pk_e replaces h_i but both were 5*G here)
    let expected = pk(200);
    assert_eq!(s4c, expected);
}

#[test]
fn test_compute_proofs_integration() {
    let secp = Secp256k1::new();

    let s = |v: u8| -> Scalar {
        let mut b = [0u8; 32];
        b[31] = v;
        Scalar::from_be_bytes(b).unwrap()
    };
    let sk_gen = |v: u8| -> SecretKey { SecretKey::from_byte_array(s(v).to_be_bytes()).unwrap() };
    let secret = |v: u8| -> Secret { Secret { s: s(v) } };
    let kp = |v: u8| -> KeyPair {
        let sk = sk_gen(v);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        KeyPair { sk, pk }
    };

    // N=1 for simplicity.
    let bli = Blinds {
        k_z: secret(10),
        k_rho: secret(11),
        k_gamma_i: vec![secret(12)],
        k_psi: secret(13),
        k_b_i: vec![secret(5)],
        k_phi_i: vec![secret(6)],
    };

    let kp_i = vec![kp(100).pk];
    let kp_t = kp(200);
    let kp_c = kp(101);
    let pk = PK {
        pk_i: kp_i,
        pk_t: kp_t.pk,
        pk_cs: kp_c.pk,
    };
    let pk_e = kp(50).pk; // Tracer group key
    let v_i = vec![kp(60).pk];

    let c = s(2);
    let alpha = s(3);

    let proofs = Proofs::compute_proofs(&bli, &pk, &pk_e, &v_i, &c, &alpha);

    assert_eq!(proofs.S4bi.len(), 1, "S4bi should have 1 element");
    assert_eq!(proofs.S4ai.len(), 1, "S4ai should have 1 element");

    let expected_s2a = PublicKey::from_secret_key(&secp, &sk_gen(11));
    assert_eq!(
        proofs.S2a, expected_s2a,
        "S2a computation inside proofs failed"
    );

    println!("Proofs computed successfully: {:?}", proofs);
}

#[test]
fn test_check_s1_full_protocol_relation() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let sk_gen = |v: u64| -> SecretKey { SecretKey::from_byte_array(s(v).to_be_bytes()).unwrap() };

    let c = s(2);
    let beta = s(3);

    let b_val = 1;
    let b_scalar = s(b_val);

    let sk1 = sk_gen(10);
    let pk1 = PublicKey::from_secret_key(&secp, &sk1);
    let r1 = s(100);
    let kb1 = s(5);

    let sk2 = sk_gen(20);
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);
    let r2 = s(200);
    let kb2 = s(7);

    let R1 = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_byte_array(r1.to_be_bytes()).unwrap(),
    );
    let R2 = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_byte_array(r2.to_be_bytes()).unwrap(),
    );

    let R = R1.combine(&R2).expect("Failed to combine R");

    let calc_z_i = |r: Scalar, sk: Scalar| -> Scalar {
        let mut sk_key = SecretKey::from_byte_array(sk.to_be_bytes()).unwrap();
        sk_key = sk_key.mul_tweak(&c).unwrap();
        sk_key = sk_key.add_tweak(&r).unwrap();
        Scalar::from_be_bytes(sk_key.secret_bytes()).unwrap()
    };

    let z1 = calc_z_i(r1, s(10));
    let z2 = calc_z_i(r2, s(20));

    let mut z_total_sk = SecretKey::from_byte_array(z1.to_be_bytes()).unwrap();
    z_total_sk = z_total_sk.add_tweak(&z2).unwrap();
    let z_total = Scalar::from_be_bytes(z_total_sk.secret_bytes()).unwrap();

    let kz = s(50);

    let mut z_hat_sk = SecretKey::from_byte_array(z_total.to_be_bytes()).unwrap();
    z_hat_sk = z_hat_sk.mul_tweak(&beta).unwrap();
    z_hat_sk = z_hat_sk.add_tweak(&kz).unwrap();
    let z_hat = Scalar::from_be_bytes(z_hat_sk.secret_bytes()).unwrap();

    let calc_b_hat = |k_b: Scalar| -> Scalar {
        let mut sk = SecretKey::from_byte_array(b_scalar.to_be_bytes()).unwrap();
        sk = sk.mul_tweak(&beta).unwrap();
        sk = sk.add_tweak(&k_b).unwrap();
        Scalar::from_be_bytes(sk.secret_bytes()).unwrap()
    };

    let b_hat1 = calc_b_hat(kb1);
    let b_hat2 = calc_b_hat(kb2);

    let k_z_secret = Secret { s: kz };
    let k_b_secrets = vec![Secret { s: kb1 }, Secret { s: kb2 }];
    let pks = vec![pk1, pk2];

    let S1 = Proofs::compute_s1(&k_z_secret, &k_b_secrets, &pks, &c);

    let result = Proofs::verify_s1(&S1, &R, &pks, &vec![b_hat1, b_hat2], &c, &beta, &z_hat);

    match result {
        Ok(valid) => assert!(valid, "S1 Check failed with full protocol relationships!"),
        Err(e) => panic!("S1 Check returned error: {}", e),
    }

    println!("S1 Protocol Relationship Test passed.");
}

#[test]
fn test_verify_sa_relationship() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let beta = s(3);
    let r_val = s(10);
    let k_r_val = s(5);

    let r_sk = SecretKey::from_byte_array(r_val.to_be_bytes()).unwrap();
    let c0 = PublicKey::from_secret_key(&secp, &r_sk);

    let k_r_sk = SecretKey::from_byte_array(k_r_val.to_be_bytes()).unwrap();
    let Sa = PublicKey::from_secret_key(&secp, &k_r_sk);

    let mut r_hat_sk = SecretKey::from_byte_array(r_val.to_be_bytes()).unwrap();
    r_hat_sk = r_hat_sk.mul_tweak(&beta).unwrap();
    r_hat_sk = r_hat_sk.add_tweak(&k_r_val).unwrap();
    let r_hat = Scalar::from_be_bytes(r_hat_sk.secret_bytes()).unwrap();

    let result = Proofs::verify_sa(&Sa, &c0, &beta, &r_hat);

    match result {
        Ok(valid) => assert!(valid, "verify_sa check failed"),
        Err(e) => panic!("verify_sa returned error: {}", e),
    }

    println!("verify_sa relationship test passed.");
}

#[test]
fn test_verify_s2b_relationship() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let beta = s(3);
    let z_val = s(100);
    let rho_val = s(5);
    let kz_val = s(20);
    let krho_val = s(2);
    let sk_t_val = s(50);

    let sk_t = SecretKey::from_byte_array(sk_t_val.to_be_bytes()).unwrap();
    let pk_t = PublicKey::from_secret_key(&secp, &sk_t);

    let z_sk = SecretKey::from_byte_array(z_val.to_be_bytes()).unwrap();
    let gz = PublicKey::from_secret_key(&secp, &z_sk);

    let pkt_rho = pk_t.mul_tweak(&secp, &rho_val).unwrap();

    let c1 = gz.combine(&pkt_rho).unwrap();

    let mut rho_hat_sk = SecretKey::from_byte_array(rho_val.to_be_bytes()).unwrap();
    rho_hat_sk = rho_hat_sk.mul_tweak(&beta).unwrap();
    rho_hat_sk = rho_hat_sk.add_tweak(&krho_val).unwrap();
    let rho_hat = Scalar::from_be_bytes(rho_hat_sk.secret_bytes()).unwrap();

    let mut z_hat_sk = SecretKey::from_byte_array(z_val.to_be_bytes()).unwrap();
    z_hat_sk = z_hat_sk.mul_tweak(&beta).unwrap();
    z_hat_sk = z_hat_sk.add_tweak(&kz_val).unwrap();
    let z_hat = Scalar::from_be_bytes(z_hat_sk.secret_bytes()).unwrap();

    let k_rho_secret = Secret { s: krho_val };
    let k_z_secret = Secret { s: kz_val };

    let S2b = Proofs::compute_s2b(&pk_t, &k_rho_secret, &k_z_secret);

    let result = Proofs::verify_s2b(&S2b, &c1, &beta, &pk_t, &rho_hat, &z_hat);

    match result {
        Ok(valid) => assert!(valid, "verify_s2b check failed"),
        Err(e) => panic!("verify_s2b returned error: {}", e),
    }

    println!("verify_s2b relationship test passed.");
}

#[test]
fn test_verify_s3b_relationship() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let beta = s(3);

    let psi_val = s(10);
    let k_psi_val = s(5);
    let k_psi = Secret { s: k_psi_val };

    // b_i vector (1, 0, 1) -> sum = 2
    let kb_scalars: Vec<Scalar> = vec![s(2), s(3), s(4)];
    let kb_secrets: Vec<Secret> = kb_scalars.iter().map(|&v| Secret { s: v }).collect();

    let h = get_second_generator_h();

    let sum_bi_sk = SecretKey::from_byte_array(s(2).to_be_bytes()).unwrap();
    let term_g = PublicKey::from_secret_key(&secp, &sum_bi_sk);

    let term_h = h.mul_tweak(&secp, &psi_val).unwrap();

    let t1 = term_g.combine(&term_h).unwrap();

    let mut psi_hat_sk = SecretKey::from_byte_array(psi_val.to_be_bytes()).unwrap();
    psi_hat_sk = psi_hat_sk.mul_tweak(&beta).unwrap();
    psi_hat_sk = psi_hat_sk.add_tweak(&k_psi_val).unwrap();
    let psi_hat = Scalar::from_be_bytes(psi_hat_sk.secret_bytes()).unwrap();

    let b_scalars = vec![s(1), s(0), s(1)];
    let mut b_hats = Vec::new();
    for i in 0..b_scalars.len() {
        if b_scalars[i] == Scalar::ZERO {
            b_hats.push(kb_scalars[i]);
            continue;
        }
        let mut sk = SecretKey::from_byte_array(b_scalars[i].to_be_bytes()).unwrap();
        sk = sk.mul_tweak(&beta).unwrap();
        sk = sk.add_tweak(&kb_scalars[i]).unwrap();
        b_hats.push(Scalar::from_be_bytes(sk.secret_bytes()).unwrap());
    }

    let sum_kb_sk = SecretKey::from_byte_array(s(9).to_be_bytes()).unwrap();
    let s3b_g = PublicKey::from_secret_key(&secp, &sum_kb_sk);
    let s3b_h = h.mul_tweak(&secp, &k_psi_val).unwrap();
    let s3b = s3b_g.combine(&s3b_h).unwrap();

    let s3b_ = Proofs::compute_s3b(&kb_secrets, &k_psi, &h);

    assert_eq!(s3b_, s3b, "compute_s3b disagrees with g^(sum k_b) * h^k_psi");

    let result = Proofs::verify_s3b(&s3b_, &t1, &h, &beta, &b_hats, &psi_hat);

    match result {
        Ok(valid) => assert!(valid, "verify_s3b check failed"),
        Err(e) => panic!("verify_s3b returned error: {}", e),
    }

    println!("verify_s3b relationship test passed.");
}

#[test]
fn test_verify_s4bi_relationship() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let beta = s(3);
    // Both signers use their own gamma_i, but we set them equal so the
    // hand-computed values below stay simple.
    let gamma_val = s(10);
    let k_gamma_val = s(5);

    let b_scalars = vec![s(1), s(0)];
    let kb_scalars = vec![s(2), s(3)];
    let kb_secrets: Vec<Secret> = kb_scalars.iter().map(|&v| Secret { s: v }).collect();

    // Shared tracer group key pk_e = 15*G, replacing the earlier per-signer
    // h_i generators.
    let pk_e_sk = SecretKey::from_byte_array(s(15).to_be_bytes()).unwrap();
    let pk_e = PublicKey::from_secret_key(&secp, &pk_e_sk);

    // v_i = g^b_i * pk_e^gamma_i
    let mut v_vec = Vec::new();
    for i in 0..2 {
        let term_h = pk_e.mul_tweak(&secp, &gamma_val).unwrap();
        if b_scalars[i] == Scalar::ZERO {
            v_vec.push(term_h);
        } else {
            let sk = SecretKey::from_byte_array(b_scalars[i].to_be_bytes()).unwrap();
            let term_g = PublicKey::from_secret_key(&secp, &sk);
            v_vec.push(term_g.combine(&term_h).unwrap());
        }
    }

    let mut g_hat_sk = SecretKey::from_byte_array(gamma_val.to_be_bytes()).unwrap();
    g_hat_sk = g_hat_sk.mul_tweak(&beta).unwrap();
    g_hat_sk = g_hat_sk.add_tweak(&k_gamma_val).unwrap();
    let gamma_hat_val = Scalar::from_be_bytes(g_hat_sk.secret_bytes()).unwrap();
    let gamma_hat = vec![gamma_hat_val, gamma_hat_val];

    let mut b_hats = Vec::new();
    for i in 0..2 {
        if b_scalars[i] == Scalar::ZERO {
            b_hats.push(kb_scalars[i]);
        } else {
            let mut sk = SecretKey::from_byte_array(b_scalars[i].to_be_bytes()).unwrap();
            sk = sk.mul_tweak(&beta).unwrap();
            sk = sk.add_tweak(&kb_scalars[i]).unwrap();
            b_hats.push(Scalar::from_be_bytes(sk.secret_bytes()).unwrap());
        }
    }

    let k_gamma_i = vec![Secret { s: k_gamma_val }, Secret { s: k_gamma_val }];
    let s4b_vec = Proofs::compute_s4bi(&kb_secrets, &k_gamma_i, &pk_e);

    let result = Proofs::verify_s4bi(&s4b_vec, &v_vec, &pk_e, &beta, &b_hats, &gamma_hat);

    match result {
        Ok(valid) => assert!(valid, "verify_s4bi check failed"),
        Err(e) => panic!("verify_s4bi returned error: {}", e),
    }

    println!("verify_s4bi relationship test passed.");
}

#[test]
fn test_verify_s4c_relationship() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };

    let beta = s(3);
    let alpha = s(2);
    let gamma = s(10);

    let b_vals = vec![1, 0];
    let b_scalars = vec![s(1), s(0)];

    let k_b_vals = vec![s(5), s(6)];
    let k_phi_vals = vec![s(7), s(8)];

    let k_b_secrets: Vec<Secret> = k_b_vals.iter().map(|&x| Secret { s: x }).collect();
    let k_phi_secrets: Vec<Secret> = k_phi_vals.iter().map(|&x| Secret { s: x }).collect();

    // Shared pk_e = 50*G, replacing per-signer h_i generators.
    let pk_e_sk = SecretKey::from_byte_array(s(50).to_be_bytes()).unwrap();
    let pk_e = PublicKey::from_secret_key(&secp, &pk_e_sk);

    let mut v_vec = Vec::new();
    for i in 0..2 {
        let b_val = b_vals[i];
        let h_term = pk_e.mul_tweak(&secp, &gamma).unwrap();

        if b_val == 0 {
            v_vec.push(h_term);
        } else {
            let g_term = PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_byte_array(s(1).to_be_bytes()).unwrap(),
            );
            v_vec.push(g_term.combine(&h_term).unwrap());
        }
    }

    let mut alpha_pows = vec![];
    let mut curr = alpha;
    for _ in 0..2 {
        alpha_pows.push(curr);
        let mut sk = SecretKey::from_byte_array(curr.to_be_bytes()).unwrap();
        sk = sk.mul_tweak(&alpha).unwrap();
        curr = Scalar::from_be_bytes(sk.secret_bytes()).unwrap();
    }

    let mut b_hats = Vec::new();
    let mut phi_hats = Vec::new();

    for i in 0..2 {
        if b_vals[i] == 0 {
            b_hats.push(k_b_vals[i]);
        } else {
            let mut sk = SecretKey::from_byte_array(b_scalars[i].to_be_bytes()).unwrap();
            sk = sk.mul_tweak(&beta).unwrap();
            sk = sk.add_tweak(&k_b_vals[i]).unwrap();
            b_hats.push(Scalar::from_be_bytes(sk.secret_bytes()).unwrap());
        }

        let term_1_minus_b = if b_vals[i] == 1 { s(0) } else { s(1) };

        if term_1_minus_b == Scalar::ZERO {
            phi_hats.push(k_phi_vals[i]);
            continue;
        }

        let mut phi_sk = SecretKey::from_byte_array(alpha_pows[i].to_be_bytes()).unwrap();
        phi_sk = phi_sk.mul_tweak(&gamma).unwrap();
        phi_sk = phi_sk.mul_tweak(&term_1_minus_b).unwrap();

        let phi_secret_scalar = Scalar::from_be_bytes(phi_sk.secret_bytes()).unwrap();

        if phi_secret_scalar == Scalar::ZERO {
            phi_hats.push(k_phi_vals[i]);
        } else {
            let mut sk_hat = SecretKey::from_byte_array(phi_secret_scalar.to_be_bytes()).unwrap();
            sk_hat = sk_hat.mul_tweak(&beta).unwrap();
            sk_hat = sk_hat.add_tweak(&k_phi_vals[i]).unwrap();
            phi_hats.push(Scalar::from_be_bytes(sk_hat.secret_bytes()).unwrap());
        }
    }

    let s4c = Proofs::compute_s4c(&v_vec, &alpha, &k_b_secrets, &pk_e, &k_phi_secrets);

    let result = Proofs::verify_s4c(&s4c, &v_vec, &pk_e, &beta, &alpha, &b_hats, &phi_hats);

    match result {
        Ok(valid) => assert!(valid, "verify_s4c check failed"),
        Err(e) => panic!("verify_s4c error: {}", e),
    }

    println!("verify_s4c relationship test passed.");
}

/// One complete, honest run of the protocol, including the tracers'
/// distributed key generation and threshold decryption.
///
/// Returns everything a verifier or tracer would need, so the negative tests
/// below can tamper with a single component of a genuinely valid transcript.
struct FullTranscript {
    pk: PK,
    tracer_shares: Vec<TracerKeyShare>,
    te: usize,
    quorum: Quorum,
    T: ElGamalCiphertext,
    R: PublicKey,
    m: Vec<u8>,
    ct: ElGamalCiphertext,
    v0: Vec<PublicKey>,
    v: Vec<PublicKey>,
    proofs: Proofs,
    sigma: Sigma,
}

impl FullTranscript {
    fn statement(&self) -> Statement<'_> {
        Statement {
            pk: &self.pk,
            T: &self.T,
            R: &self.R,
            m: &self.m,
            ct: &self.ct,
            v0: &self.v0,
            v: &self.v,
        }
    }

    /// Runs the tracing side: threshold-decrypts ct and v, and recovers the
    /// quorum bits.
    fn trace(&self) -> (Vec<u8>, Gt) {
        let input =
            DecryptionInput::from_public_keys(&self.ct.c0, &self.ct.c1, &self.v0, &self.v);
        let vks = qual_and_vks(&self.tracer_shares);

        let (g_z_prime, g_bits) =
            dkg::threshold_decrypt(&input, &self.tracer_shares[..self.te], &vks)
                .expect("threshold decryption must succeed");

        let bits: Vec<u8> = g_bits
            .iter()
            .enumerate()
            .map(|(i, g_bit)| dkg::decode_bit(g_bit, i).expect("bit decryption failed"))
            .collect();

        (bits, g_z_prime)
    }
}

fn run_protocol(n: usize, t: usize, n3: usize, te: usize, m: &[u8]) -> FullTranscript {
    // --- Tracers: distributed key generation ---
    let tracer_shares = dkg::run_dkg(te, n3).expect("tracer DKG must succeed");
    let pk_e = tracer_shares[0].pk_e_as_public_key();

    // --- Setup ---
    let signers: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();
    let kp_cs = KeyPair::create(); // Combiner

    let pk = PK::set(&signers, &kp_cs, pk_e);
    let quorum = Quorum::choose(n, t, &signers);

    // --- Round 1: commitments ---
    let commits: Vec<Commit> = (0..n).map(|_| Commit::commit()).collect();
    let commitments: Vec<Commitment> = commits.iter().map(Commitment::set).collect();
    let R = Commitment::aggregate(&commitments, &quorum).expect("R aggregation failed");

    // --- Combiner encrypts the threshold, then derives c ---
    let psi = Secret::create();
    let t_scalar = {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&(t as u64).to_be_bytes());
        Scalar::from_be_bytes(bytes).unwrap()
    };
    let T = ElGamalCiphertext::encrypt_value(&psi, &t_scalar);

    let c = compute_challenge_c(&pk, &T, &R, m);

    // --- Round 2: signature shares ---
    let shares: Vec<Sign> = (0..n)
        .map(|i| Sign::sign(&commits[i], &signers[i], &c))
        .collect();
    let z = Sign::aggregate(&shares, &quorum);

    // --- Combiner: encrypt z, encrypt the quorum bits under pk_e ---
    let rho = Secret::create();
    let ct = ElGamalCiphertext::encrypt(&rho, &z, &pk);

    let (gammas, ciphertexts) = encrypt_bits_threshold(&quorum, &pk_e);
    let v0: Vec<PublicKey> = ciphertexts.iter().map(|c| c.c0).collect();
    let v: Vec<PublicKey> = ciphertexts.iter().map(|c| c.c1).collect();

    // alpha is only drawn now, once ct / v0 / v are fixed.
    let alpha = Statement {
        pk: &pk,
        T: &T,
        R: &R,
        m,
        ct: &ct,
        v0: &v0,
        v: &v,
    }
    .alpha(&c);

    let phis = Phis::set(&alpha, &gammas, &quorum);

    // --- Proof: commitments first, then beta, then responses ---
    let blinds = Blinds::set(n);
    let proofs = Proofs::compute_proofs(&blinds, &pk, &pk_e, &v, &c, &alpha);

    let beta = Statement {
        pk: &pk,
        T: &T,
        R: &R,
        m,
        ct: &ct,
        v0: &v0,
        v: &v,
    }
    .beta(&alpha, &proofs);

    let witnesses = Witnesses::set(z, rho, &gammas, psi, &quorum, &phis);
    let hats = Hats::set(&beta, &witnesses, &blinds);

    let pi = Pi { beta, hats };
    let sigma = Sigma::sign(&kp_cs, m, &R, &ct, pi);

    FullTranscript {
        pk,
        tracer_shares,
        te,
        quorum,
        T,
        R,
        m: m.to_vec(),
        ct,
        v0,
        v,
        proofs,
        sigma,
    }
}

#[test]
fn test_end_to_end_protocol_verifies_and_traces_one_tracer() {
    end_to_end_verifies_and_traces(6, 4, 1, 1);
}

#[test]
fn test_end_to_end_protocol_verifies_and_traces_five_tracers() {
    // t_e = floor(2*5/3) + 1 = 4.
    end_to_end_verifies_and_traces(6, 4, 5, 4);
}

fn end_to_end_verifies_and_traces(n: usize, t: usize, n3: usize, te: usize) {
    let m: &[u8] = b"TAPS_TT end-to-end";
    let tr = run_protocol(n, t, n3, te, m);

    // 1. The combiner's signature over the package.
    assert!(
        Sigma::verify(&tr.pk, m, &tr.sigma).expect("sigma verification errored"),
        "Sigma must verify"
    );

    // 2. The accountability proof - public data only, challenges re-derived.
    assert!(
        Proofs::verify(&tr.proofs, &tr.sigma, &tr.statement()).expect("proof verification errored"),
        "Proof must verify"
    );

    // 3. Tracing: recover the quorum bits, using t_e cooperating tracers.
    let (bits, g_z_prime) = tr.trace();
    let expected: Vec<u8> = tr.quorum.participants.iter().map(|(_, b)| *b).collect();
    assert_eq!(bits, expected, "Traced bits must match the real quorum");
    assert_eq!(
        bits.iter().filter(|&&b| b == 1).count(),
        t,
        "Exactly t signers must be traced"
    );

    // 4. Tracing: the decrypted signature must be the one that quorum produces.
    let c = tr.statement().c();
    let quo = Quorum::set(&tr.pk, &bits);
    let expected_g_z = schnorr_signature(&tr.R, &quo, &c);
    assert_eq!(
        g_z_prime,
        Gt::from_public_key(&expected_g_z),
        "Decrypted g^z must equal R * prod(pk_i)^c over the traced quorum"
    );
}

#[test]
fn test_verify_rejects_tampered_response() {
    let tr = run_protocol(4, 3, 1, 1, b"tamper the response");

    let mut sigma = tr.sigma.clone();
    // Bump z_hat by one. beta is unchanged, so the transcript check passes and
    // the algebraic S1 check is what must catch this.
    sigma.pi.hats.z_hat = {
        let sk = SecretKey::from_byte_array(sigma.pi.hats.z_hat.to_be_bytes()).unwrap();
        Scalar::from_be_bytes(sk.add_tweak(&Scalar::ONE).unwrap().secret_bytes()).unwrap()
    };

    let res = Proofs::verify(&tr.proofs, &sigma, &tr.statement());
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "A tampered z_hat must not verify, got {:?}",
        res
    );
}

#[test]
fn test_verify_rejects_prover_chosen_beta() {
    let tr = run_protocol(4, 3, 1, 1, b"prover chosen beta");

    let mut sigma = tr.sigma.clone();
    sigma.pi.beta = Scalar::ONE;

    let res = Proofs::verify(&tr.proofs, &sigma, &tr.statement());
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "A prover-chosen beta must be rejected, got {:?}",
        res
    );
}

#[test]
fn test_verify_rejects_tampered_statement() {
    let tr = run_protocol(4, 3, 1, 1, b"tamper the statement");

    // Swapping out an encrypted bit changes the transcript, so the re-derived
    // beta no longer matches the one the responses were computed against.
    let mut v_alt = tr.v.clone();
    v_alt.swap(0, 1);
    let stmt = Statement {
        v: &v_alt,
        ..tr.statement()
    };

    let res = Proofs::verify(&tr.proofs, &tr.sigma, &stmt);
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "A tampered v vector must be rejected, got {:?}",
        res
    );

    // Same for the message.
    let stmt = Statement {
        m: b"a different message",
        ..tr.statement()
    };
    let res = Proofs::verify(&tr.proofs, &tr.sigma, &stmt);
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "A different message must be rejected, got {:?}",
        res
    );
}

#[test]
fn test_sigma_rejects_other_message() {
    let tr = run_protocol(3, 2, 1, 1, b"the real message");

    let res = Sigma::verify(&tr.pk, b"not the real message", &tr.sigma);
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "Sigma must not verify against a different message, got {:?}",
        res
    );
}

#[test]
fn test_end_to_end_full_and_minimal_quorums() {
    // t == n (everyone signs) and t == 1 (a single signer) are the edge cases
    // where the b_i vector is all-ones / almost all-zeros.
    for (n, t) in [(4usize, 4usize), (4, 1)] {
        let m: &[u8] = b"edge case quorum";
        let tr = run_protocol(n, t, 5, 4, m);

        assert!(
            Proofs::verify(&tr.proofs, &tr.sigma, &tr.statement()).expect("verification errored"),
            "Proof must verify for n={} t={}",
            n,
            t
        );

        let (bits, _) = tr.trace();
        assert_eq!(bits.iter().filter(|&&b| b == 1).count(), t);
    }
}

/// End-to-end run with 100 signers, threshold `floor(n/2)+1`, exercised
/// against both a single tracer and five tracers - the two configurations
/// this codebase is expected to run without error.
#[test]
fn test_end_to_end_one_hundred_signers_one_tracer() {
    let n = 100;
    let t = n / 2 + 1;
    end_to_end_verifies_and_traces(n, t, 1, 1);
}

#[test]
fn test_end_to_end_one_hundred_signers_five_tracers() {
    let n = 100;
    let t = n / 2 + 1;
    // t_e = floor(2*5/3) + 1 = 4.
    end_to_end_verifies_and_traces(n, t, 5, 4);
}

#[test]
fn C() {
    // 1. Setup
    let c = Scalar::ONE; // Use 1 for simplicity (Result should be R + Sum(PKs))

    // Create Signers
    let kp1 = KeyPair::create();
    let kp2 = KeyPair::create();
    let signers = vec![kp1.clone(), kp2.clone()];

    // Create Quorum (Both present)
    let quorum = Quorum::choose(2, 2, &signers);

    // Create Random R
    let r_kp = KeyPair::create();
    let R = r_kp.pk;

    // 2. Compute Actual
    let computed_pk = schnorr_signature(&R, &quorum, &c);

    // 3. Compute Expected Manually
    // Expected = R + pk1 + pk2 (since c=1 and both bits=1)
    let expected_pk = R.combine(&kp1.pk).unwrap().combine(&kp2.pk).unwrap();

    assert_eq!(computed_pk, expected_pk, "Schnorr target key mismatch");
}

#[test]
fn test_sigma_sign_schnorr_signature() {
    // Create Signer KeyPair (sk used for signing)
    let kp_cs = KeyPair::create();

    // Create Dummy Aggregate Nonce R
    let r_dummy = KeyPair::create().pk;

    // Create Dummy Ciphertext (ct)
    let ct_dummy = ElGamalCiphertext {
        c0: KeyPair::create().pk,
        c1: KeyPair::create().pk,
    };

    // Create Dummy Pi (Hats)
    let hats_dummy = Hats {
        z_hat: Scalar::ONE,
        rho_hat: Scalar::ONE,
        gamma_hat: vec![Scalar::ONE],
        psi_hat: Scalar::ONE,
        b_hat: vec![Scalar::ONE, Scalar::ZERO],
        phi_hat: vec![Scalar::ONE, Scalar::ZERO],
    };

    let pi = Pi {
        beta: Scalar::ONE,
        hats: hats_dummy,
    };

    let message = b"Test Message for Sigma";

    let sigma = Sigma::sign(&kp_cs, message, &r_dummy, &ct_dummy, pi);

    assert_eq!(sigma.R, r_dummy, "Sigma R must match input R");
    assert_eq!(sigma.ct, ct_dummy, "Sigma ct must match input ct");

    let _s_response = sigma.tg;
    let _r_commitment = sigma.comm;

    println!("Schnorr Signature generated successfully.");
    println!("Sigma Comm (R_schnorr): {:?}", sigma.comm);
    println!("Sigma Response (s): {:?}", sigma.tg);
}

#[test]
fn test_sigma_verify_schnorr_signature() {
    let secp = Secp256k1::new();

    let s = |v: u64| -> Scalar {
        let mut bytes = [0u8; 32];
        let v_bytes = v.to_be_bytes();
        bytes[24..32].copy_from_slice(&v_bytes);
        Scalar::from_be_bytes(bytes).unwrap()
    };
    let sk_gen = |v: u64| -> SecretKey { SecretKey::from_byte_array(s(v).to_be_bytes()).unwrap() };
    let pk_gen = |v: u64| -> PublicKey { PublicKey::from_secret_key(&secp, &sk_gen(v)) };
    let kp_i = vec![pk_gen(100)];
    let kp_cs = KeyPair::create();
    let kp_t = pk_gen(300);
    let pk = PK {
        pk_i: kp_i,
        pk_t: kp_t,
        pk_cs: kp_cs.pk,
    };
    let message = b"Verify Me";

    let hats_dummy = Hats {
        z_hat: Scalar::ONE,
        rho_hat: Scalar::ONE,
        gamma_hat: vec![Scalar::ONE],
        psi_hat: Scalar::ONE,
        b_hat: vec![Scalar::ONE],
        phi_hat: vec![Scalar::ONE],
    };

    let pi = Pi {
        beta: Scalar::ONE,
        hats: hats_dummy,
    };

    let r_dummy = KeyPair::create().pk;
    let ct_dummy = ElGamalCiphertext {
        c0: KeyPair::create().pk,
        c1: KeyPair::create().pk,
    };

    let sigma = Sigma::sign(&kp_cs, message, &r_dummy, &ct_dummy, pi);

    let result = Sigma::verify(&pk, message, &sigma);

    assert!(
        result.is_ok(),
        "Verification returned error: {:?}",
        result.err()
    );
    assert!(result.unwrap(), "Verification logic returned false");

    println!("Schnorr Signature verified successfully.");
}

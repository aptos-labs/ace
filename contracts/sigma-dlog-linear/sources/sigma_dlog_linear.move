// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Generalized Schnorr proof for linear relations among discrete logarithms.
///
/// This is a sigma protocol, made non-interactive via Fiat-Shamir, for proving
/// knowledge of a witness vector s[0..n-1] satisfying m public linear
/// representation equations:
///
///     s[0] * B[0][0] + ... + s[n-1] * B[0][n-1] = P[0]
///     ...
///     s[0] * B[m-1][0] + ... + s[n-1] * B[m-1][n-1] = P[m-1]
///
/// Public statement:
/// - B: an m-by-n matrix of public group elements, flattened row-major as
///   b_vals[i*n + j] == B[i][j].
/// - P: a vector of m public group elements.
///
/// Witness:
/// - s: a vector of n scalars.
///
/// Proof shape:
/// - sample randomizers r[0..n-1]
/// - compute commitments T[i] = sum_j r[j] * B[i][j]
/// - Fiat-Shamir challenge c = H(shape, B, P, T)
/// - responses z[j] = r[j] + c * s[j]
///
/// Verification checks, for every row i:
///
///     sum_j z[j] * B[i][j] == T[i] + c * P[i]
///
/// This is the standard generalized Schnorr / Camenisch-Stadler construction
/// for proving linear relations among discrete logarithms. Chaum-Pedersen DLEQ
/// is a special case where the same witness appears in two one-column rows.
///
/// References:
/// - Camenisch and Stadler, "Proof Systems for General Statements about
///   Discrete Logarithms", ETH Zurich technical report 260, 1997.
///   https://www.research-collection.ethz.ch/handle/20.500.11850/69316
/// - Chaum and Pedersen, "Wallet Databases with Observers", CRYPTO 1992.
///   https://iacr.org/cryptodb/data/paper.php?pubkey=1131
module ace::sigma_dlog_linear {
    use std::bcs;
    use std::error;
    use std::vector::range;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use ace::group;
    use ace::fiat_shamir_transform;
    #[test_only]
    use aptos_framework::randomness;

    const E_INVALID_DIMENSIONS: u64 = 1;
    const E_INCONSISTENT_SCHEME: u64 = 2;

    /// Non-interactive proof: T commitments plus z responses.
    struct Proof has copy, drop, store {
        t_vals: vector<group::Element>,
        z_vals: vector<group::Scalar>,
    }

    public fun deserialize_proof(stream: &mut BCSStream): Proof {
        let t_vals = bcs_stream::deserialize_vector(stream, |s|group::deserialize_element(s));
        let z_vals = bcs_stream::deserialize_vector(stream,|s|group::deserialize_scalar(s));
        Proof { t_vals, z_vals }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// Test-only prover for the sigma protocol.
    ///
    /// Production clients should implement the same transcript construction
    /// off-chain. Callers should prepend their application-specific domain
    /// separator and context to `trx` before calling this function or `verify`.
    public fun prove(
        trx: &mut fiat_shamir_transform::Transcript,
        b_vals: &vector<group::Element>, p_vals: &vector<group::Element>, // statement
        s_vals: &vector<group::Scalar> // witness
    ): Proof {
        let num_secrets = s_vals.length();
        let num_constraints = p_vals.length();
        assert!(num_secrets > 0 && num_constraints > 0, error::invalid_argument(E_INVALID_DIMENSIONS));
        assert!(num_secrets * num_constraints == b_vals.length(), error::invalid_argument(E_INVALID_DIMENSIONS));
        let scheme = group::scalar_scheme(&s_vals[0]);
        assert!(b_vals.map_ref(|b_val| group::element_scheme(b_val)).all(|s| *s == scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        assert!(p_vals.map_ref(|p_val| group::element_scheme(p_val)).all(|s| *s == scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        assert!(s_vals.map_ref(|s_val| group::scalar_scheme(s_val)).all(|s| *s == scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));

        append_statement(trx, b_vals, p_vals, num_secrets, num_constraints);
        let r_vals = range(0, num_secrets).map(|_| group::rand_scalar(scheme));
        let t_vals = range(0, num_constraints).map(|idx| group::msm(b_vals.slice(num_secrets*idx, num_secrets*(idx+1)), r_vals));
        t_vals.for_each_ref(|t_val|fiat_shamir_transform::append_group_element(trx, t_val));
        let c = fiat_shamir_transform::hash_to_scalar(trx, scheme);
        let z_vals = range(0, num_secrets).map(|i| group::scalar_add(&r_vals[i], &group::scalar_mul(&c, &s_vals[i])));
        Proof { t_vals, z_vals }
    }

    public fun verify(
        trx: &mut fiat_shamir_transform::Transcript,
        b_vals: &vector<group::Element>, p_vals: &vector<group::Element>, // statement
        proof: &Proof
    ): bool {
        let num_constraints = p_vals.length();
        let num_secrets = proof.z_vals.length();
        if (num_secrets == 0 || num_constraints == 0) return false;
        if (proof.t_vals.length() != num_constraints) return false;
        if (num_secrets * num_constraints != b_vals.length()) return false;
        let scheme = group::element_scheme(&b_vals[0]);
        if (!b_vals.map_ref(|b_val| group::element_scheme(b_val)).all(|s| *s == scheme)) return false;
        if (!p_vals.map_ref(|p_val| group::element_scheme(p_val)).all(|s| *s == scheme)) return false;
        if (!proof.t_vals.map_ref(|t_val| group::element_scheme(t_val)).all(|s| *s == scheme)) return false;
        if (!proof.z_vals.map_ref(|z_val| group::scalar_scheme(z_val)).all(|s| *s == scheme)) return false;

        append_statement(trx, b_vals, p_vals, num_secrets, num_constraints);
        proof.t_vals.for_each_ref(|t_val|fiat_shamir_transform::append_group_element(trx, t_val));
        let c = fiat_shamir_transform::hash_to_scalar(trx, scheme);
        range(0, num_constraints).all(|i|{
            let idx = *i;
            let lhs = group::element_add(&proof.t_vals[idx], &group::scale_element(&p_vals[idx], &c));
            let rhs = group::msm(b_vals.slice(num_secrets*idx, num_secrets*(idx+1)), proof.z_vals);
            group::element_eq(&lhs, &rhs)
        })
    }

    /// Append the public statement to the Fiat-Shamir transcript.
    ///
    /// The matrix dimensions are included to prevent shape ambiguity for the
    /// same flattened element sequence.
    fun append_statement(
        trx: &mut fiat_shamir_transform::Transcript,
        b_vals: &vector<group::Element>,
        p_vals: &vector<group::Element>,
        num_secrets: u64,
        num_constraints: u64,
    ) {
        fiat_shamir_transform::append_raw_bytes(trx, bcs::to_bytes(&num_secrets));
        fiat_shamir_transform::append_raw_bytes(trx, bcs::to_bytes(&num_constraints));
        b_vals.for_each_ref(|b_val|fiat_shamir_transform::append_group_element(trx, b_val));
        p_vals.for_each_ref(|p_val|fiat_shamir_transform::append_group_element(trx, p_val));
    }

    #[test_only]
    fun sample_statement(
        num_secrets: u64,
        num_constraints: u64,
        scheme: u8,
    ): (vector<group::Element>, vector<group::Element>, vector<group::Scalar>) {
        let s_vals = range(0, num_secrets).map(|_|group::rand_scalar(scheme));
        let b_vals = range(0, num_secrets*num_constraints).map(|_|group::rand_element(scheme));
        let p_vals = range(0, num_constraints).map(|i|group::msm(b_vals.slice(num_secrets*i, num_secrets*(i+1)), s_vals));
        (b_vals, p_vals, s_vals)
    }

    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let num_secrets = 3;
        let num_constraints = 4;
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, s_vals) = sample_statement(num_secrets, num_constraints, scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &s_vals);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(verify(&mut verifier_trx, &b_vals, &p_vals, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_witness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, _) = sample_statement(3, 4, scheme);
        let wrong_s_vals = range(0, 3).map(|_|group::rand_scalar(scheme));
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &wrong_s_vals);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b_vals, &p_vals, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_statement(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, s_vals) = sample_statement(3, 4, scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &s_vals);

        p_vals[0] = group::rand_element(scheme);
        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b_vals, &p_vals, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_prefix(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, s_vals) = sample_statement(3, 4, scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &s_vals);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"DIFFERENT_PREFIX");
        assert!(!verify(&mut verifier_trx, &b_vals, &p_vals, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun bad_dimensions_return_false(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, s_vals) = sample_statement(3, 4, scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &s_vals);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b_vals, &p_vals.slice(0, 3), &proof), 999);

        let empty_proof = Proof { t_vals: vector[], z_vals: vector[] };
        let verifier_trx_empty = fiat_shamir_transform::new_transcript();
        assert!(!verify(&mut verifier_trx_empty, &vector[], &vector[], &empty_proof), 1000);
    }

    #[test(framework = @0x1)]
    fun mixed_scheme_returns_false(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let (b_vals, p_vals, s_vals) = sample_statement(3, 4, scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b_vals, &p_vals, &s_vals);

        p_vals[0] = group::rand_element(group::scheme_bls12381_g2());
        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b_vals, &p_vals, &proof), 999);
    }
}

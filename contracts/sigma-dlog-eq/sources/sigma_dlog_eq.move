// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Protocol to prove knowledge of scalar `s` such that `s*B0==P0, s*B1==P1`
/// for public group elements `B0, B1, P0, P1`.
module ace::sigma_dlog_eq {
    use aptos_std::bcs_stream::BCSStream;
    use ace::fiat_shamir_transform;
    use ace::group;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_std::bcs_stream;

    struct Proof has copy, drop, store {
        t0: group::Element,
        t1: group::Element,
        s: group::Scalar,
    }

    public fun deserialize_proof(stream: &mut BCSStream): Proof {
        let t0 = group::deserialize_element(stream);
        let t1 = group::deserialize_element(stream);
        let s = group::deserialize_scalar(stream);
        Proof { t0, t1, s }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element,
        p0: &group::Element,
        b1: &group::Element,
        p1: &group::Element, // statement
        s: &group::Scalar    // witness
    ): Proof {
        let scheme = group::element_scheme(b0);
        fiat_shamir_transform::append_group_element(trx, b0);
        fiat_shamir_transform::append_group_element(trx, p0);
        fiat_shamir_transform::append_group_element(trx, b1);
        fiat_shamir_transform::append_group_element(trx, p1);
        let r = group::rand_scalar(scheme);
        let t0 = group::scale_element(b0, &r);
        let t1 = group::scale_element(b1, &r);
        fiat_shamir_transform::append_group_element(trx, &t0);
        fiat_shamir_transform::append_group_element(trx, &t1);
        let c = fiat_shamir_transform::hash_to_scalar(trx, scheme);
        let s = group::scalar_add(&r, &group::scalar_mul(&c, s));
        Proof { t0, t1, s }
    }

    public fun verify(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element,
        p0: &group::Element,
        b1: &group::Element,
        p1: &group::Element, // statement
        proof: &Proof
    ): bool {
        let scheme = group::element_scheme(b0);
        fiat_shamir_transform::append_group_element(trx, b0);
        fiat_shamir_transform::append_group_element(trx, p0);
        fiat_shamir_transform::append_group_element(trx, b1);
        fiat_shamir_transform::append_group_element(trx, p1);
        fiat_shamir_transform::append_group_element(trx, &proof.t0);
        fiat_shamir_transform::append_group_element(trx, &proof.t1);
        let c = fiat_shamir_transform::hash_to_scalar(trx, scheme);
        group::scale_element(b0, &proof.s)
            == group::element_add(&proof.t0, &group::scale_element(p0, &c))
            && group::scale_element(b1, &proof.s)
                == group::element_add(&proof.t1, &group::scale_element(p1, &c))
    }

    #[test]
    fun serde_golden() {
        // BCS encoding of Element::Bls12381G1 wrapping the BLS12-381 G1 generator:
        //   00           = variant 0 (BLS12381G1)
        //   30           = ULEB128(48), byte length of compressed G1 point
        //   97f1...c6bb  = 48-byte FormatG1Compr: compression flag | big-endian x-coordinate
        let g1_gen_elem_bcs = x"003097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

        // BCS encoding of Scalar::Bls12381G1 wrapping Fr scalar 1:
        //   00           = variant 0 (BLS12381G1)
        //   20           = ULEB128(32), byte length of Fr scalar
        //   0100...00    = 32-byte FormatFrLsb: value 1 in little-endian
        let fr_one_scalar_bcs = x"00200100000000000000000000000000000000000000000000000000000000000000";

        // Proof { t0: G, t1: G, s: 1 } serializes as t0-bcs || t1-bcs || s-bcs (134 bytes)
        let proof_bcs = x"003097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb003097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00200100000000000000000000000000000000000000000000000000000000000000";

        // element round-trip
        let t = group::element_from_bytes(g1_gen_elem_bcs);
        assert!(bcs::to_bytes(&t) == g1_gen_elem_bcs, 1);

        // scalar serialization
        let s = group::scalar_from_u64(group::scheme_bls12381_g1(), 1);
        assert!(bcs::to_bytes(&s) == fr_one_scalar_bcs, 2);

        // proof construction round-trip
        let proof = Proof { t0: t, t1: t, s };
        assert!(bcs::to_bytes(&proof) == proof_bcs, 3);

        // proof deserialize round-trip
        let proof2 = deserialize_proof(&mut bcs_stream::new(proof_bcs));
        assert!(bcs::to_bytes(&proof2) == proof_bcs, 4);
    }

    #[test(framework = @0x1)]
    fun completeness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let s = group::rand_scalar(scheme);
        let b0 = group::rand_element(scheme);
        let b1 = group::rand_element(scheme);
        let p0 = group::scale_element(&b0, &s);
        let p1 = group::scale_element(&b1, &s);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b0, &p0, &b1, &p1, &s);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(verify(&mut verifier_trx, &b0, &p0, &b1, &p1, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_witness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let s = group::rand_scalar(scheme);
        let s_wrong = group::rand_scalar(scheme);
        let b0 = group::rand_element(scheme);
        let b1 = group::rand_element(scheme);
        let p0 = group::scale_element(&b0, &s);
        let p1 = group::scale_element(&b1, &s);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b0, &p0, &b1, &p1, &s_wrong);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b0, &p0, &b1, &p1, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_statement(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let s = group::rand_scalar(scheme);
        let b0 = group::rand_element(scheme);
        let b1 = group::rand_element(scheme);
        let p0 = group::scale_element(&b0, &s);
        let p1 = group::scale_element(&b1, &s);
        let p0_wrong = group::rand_element(scheme);
        let p1_wrong = group::rand_element(scheme);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b0, &p0, &b1, &p1, &s);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(!verify(&mut verifier_trx, &b0, &p0_wrong, &b1, &p1_wrong, &proof), 999);
    }

    #[test(framework = @0x1)]
    fun wrong_prefix(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let s = group::rand_scalar(scheme);
        let b0 = group::rand_element(scheme);
        let b1 = group::rand_element(scheme);
        let p0 = group::scale_element(&b0, &s);
        let p1 = group::scale_element(&b1, &s);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b0, &p0, &b1, &p1, &s);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"DIFFERENT_PREFIX");
        assert!(!verify(&mut verifier_trx, &b0, &p0, &b1, &p1, &proof), 999);
    }
}

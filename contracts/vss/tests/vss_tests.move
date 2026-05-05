// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module ace::vss_tests {
    use ace::vss;
    use ace::group;
    use ace::group_bls12381_g1;
    use ace::group_bls12381_g2;
    use aptos_std::bcs_stream;

    // BLS12-381 G1 generator in compressed form (48 bytes, standard format).
    // First byte = 0x97 = 0x17 (x_coord MSB) | 0x80 (compressed flag).
    const G1_GENERATOR_COMPR: vector<u8> = x"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    // Wrap 48-byte raw G1 bytes in BCS bytes-field encoding: [uleb128(48)][48B].
    fun g1_bcs_bytes(raw: vector<u8>): vector<u8> {
        let bcs_bytes = vector[0x30u8]; // uleb128(48) = 0x30
        bcs_bytes.append(raw);
        bcs_bytes
    }

    fun g1_generator_point(): group_bls12381_g1::PublicPoint {
        group_bls12381_g1::deserialize_public_point(
            &mut bcs_stream::new(g1_bcs_bytes(G1_GENERATOR_COMPR))
        )
    }

    // ── DC1 golden parse tests ───────────────────────────────────────────────

    // 3 holders, all acked → all None.
    // Bytes: 03 00 00 00
    #[test]
    fun test_dc1_all_none() {
        let bytes = x"03000000";
        let dc1 = vss::dc1_from_bytes_for_testing(bytes);
        assert!(vss::dc1_len(&dc1) == 3, 0);
        assert!(vss::dc1_is_none_at(&dc1, 0), 1);
        assert!(vss::dc1_is_none_at(&dc1, 1), 2);
        assert!(vss::dc1_is_none_at(&dc1, 2), 3);
    }

    // 3 holders: [None, None, Some(scalar=1)].
    // Bytes: 03 00 00 01 00 20 [01 + 00*31]
    #[test]
    fun test_dc1_with_one_revealed() {
        let bytes = x"0300000100200100000000000000000000000000000000000000000000000000000000000000";
        let dc1 = vss::dc1_from_bytes_for_testing(bytes);
        assert!(vss::dc1_len(&dc1) == 3, 0);
        assert!(vss::dc1_is_none_at(&dc1, 0), 1);
        assert!(vss::dc1_is_none_at(&dc1, 1), 2);
        assert!(vss::dc1_is_some_at(&dc1, 2), 3);
    }

    // ── group_bls12381_g1 scalar and point tests ─────────────────────────────

    // Verify 3 * 4 == 12 in Fr by checking G^(3*4) == G^12.
    #[test]
    fun test_scalar_mul() {
        let a = group_bls12381_g1::scalar_from_u64(3);
        let b = group_bls12381_g1::scalar_from_u64(4);
        let c = group_bls12381_g1::scalar_mul(&a, &b);
        let twelve = group_bls12381_g1::scalar_from_u64(12);

        let g = g1_generator_point();
        let c_g = group_bls12381_g1::scale_point(&g, &c);
        let twelve_g = group_bls12381_g1::scale_point(&g, &twelve);
        assert!(group_bls12381_g1::point_eq(&c_g, &twelve_g), 0);
    }

    // MSM([G, G], [3, 9]) == scale_point(G, 12).
    #[test]
    fun test_msm() {
        let s3 = group_bls12381_g1::scalar_from_u64(3);
        let s9 = group_bls12381_g1::scalar_from_u64(9);
        let s12 = group_bls12381_g1::scalar_from_u64(12);

        let g = g1_generator_point();
        let msm_result = group_bls12381_g1::msm(vector[g, g], vector[s3, s9]);
        let twelve_g = group_bls12381_g1::scale_point(&g, &s12);
        assert!(group_bls12381_g1::point_eq(&msm_result, &twelve_g), 0);
    }

    // ── group_bls12381_g2 sibling tests ───────────────────────────────────────

    fun g2_hashed_point(): group_bls12381_g2::PublicPoint {
        group_bls12381_g2::element_from_hash(&b"test-g2-base")
    }

    // Verify 3 * 4 == 12 in Fr by checking G^(3*4) == G^12, where G is a hashed-to-G2 point.
    #[test]
    fun test_scalar_mul_g2() {
        let a = group_bls12381_g2::scalar_from_u64(3);
        let b = group_bls12381_g2::scalar_from_u64(4);
        let c = group_bls12381_g2::scalar_mul(&a, &b);
        let twelve = group_bls12381_g2::scalar_from_u64(12);

        let g = g2_hashed_point();
        let c_g = group_bls12381_g2::scale_point(&g, &c);
        let twelve_g = group_bls12381_g2::scale_point(&g, &twelve);
        assert!(group_bls12381_g2::point_eq(&c_g, &twelve_g), 0);
    }

    #[test]
    fun test_msm_g2() {
        let s3 = group_bls12381_g2::scalar_from_u64(3);
        let s9 = group_bls12381_g2::scalar_from_u64(9);
        let s12 = group_bls12381_g2::scalar_from_u64(12);

        let g = g2_hashed_point();
        let msm_result = group_bls12381_g2::msm(vector[g, g], vector[s3, s9]);
        let twelve_g = group_bls12381_g2::scale_point(&g, &s12);
        assert!(group_bls12381_g2::point_eq(&msm_result, &twelve_g), 0);
    }

    // ── Abstract group::* API tests (cover the dispatch layer) ────────────────

    #[test]
    fun test_abstract_group_g1_arithmetic() {
        let scheme = group::scheme_bls12381_g1();
        let three = group::scalar_from_u64(scheme, 3);
        let four = group::scalar_from_u64(scheme, 4);
        let twelve = group::scalar_from_u64(scheme, 12);
        let product = group::scalar_mul(&three, &four);
        assert!(group::scalar_eq(&product, &twelve), 0);

        let g = group::element_from_hash(scheme, &b"abstract-g1-base");
        let g_twelve = group::scale_element(&g, &twelve);
        let msm_result = group::msm(vector[g, g], vector[three, group::scalar_from_u64(scheme, 9)]);
        assert!(group::element_eq(&msm_result, &g_twelve), 1);
    }

    #[test]
    fun test_abstract_group_g2_arithmetic() {
        let scheme = group::scheme_bls12381_g2();
        let three = group::scalar_from_u64(scheme, 3);
        let four = group::scalar_from_u64(scheme, 4);
        let twelve = group::scalar_from_u64(scheme, 12);
        let product = group::scalar_mul(&three, &four);
        assert!(group::scalar_eq(&product, &twelve), 0);

        let g = group::element_from_hash(scheme, &b"abstract-g2-base");
        let g_twelve = group::scale_element(&g, &twelve);
        let msm_result = group::msm(vector[g, g], vector[three, group::scalar_from_u64(scheme, 9)]);
        assert!(group::element_eq(&msm_result, &g_twelve), 1);
    }

    // Cross-scheme arithmetic must abort: mixing G1 and G2 elements is unsupported.
    #[test]
    #[expected_failure]
    fun test_abstract_group_cross_scheme_add_rejected() {
        let g1 = group::element_from_hash(group::scheme_bls12381_g1(), &b"x");
        let g2 = group::element_from_hash(group::scheme_bls12381_g2(), &b"x");
        group::element_add(&g1, &g2);
    }

    // Feldman verification: for polynomial f(x) = a0 + a1*x with a0=1, a1=2,
    // commitment C = [g^1, g^2]. Verify g^{f(1)} == MSM(C, [1, 1]) = g^{1+2} = g^3.
    // Tested over G2 to exercise the abstract layer with the second scheme.
    #[test]
    fun test_feldman_verification_abstract_g2() {
        let scheme = group::scheme_bls12381_g2();
        let a0 = group::scalar_from_u64(scheme, 1);
        let a1 = group::scalar_from_u64(scheme, 2);

        let g = group::element_from_hash(scheme, &b"feldman-g2-base");
        let c0 = group::scale_element(&g, &a0);
        let c1 = group::scale_element(&g, &a1);

        // f(1) = 3.
        let one = group::scalar_from_u64(scheme, 1);
        let f1 = group::scalar_from_u64(scheme, 3);
        let lhs = group::scale_element(&g, &f1);
        let rhs = group::msm(vector[c0, c1], vector[one, one]);
        assert!(group::element_eq(&lhs, &rhs), 0);

        // f(2) = 5.
        let two = group::scalar_from_u64(scheme, 2);
        let f2 = group::scalar_from_u64(scheme, 5);
        let lhs2 = group::scale_element(&g, &f2);
        let rhs2 = group::msm(vector[c0, c1], vector[one, two]);
        assert!(group::element_eq(&lhs2, &rhs2), 1);
    }

    // Feldman verification: for polynomial f(x) = a0 + a1*x with a0=1, a1=2,
    // commitment C = [g^1, g^2]. Verify g^{f(1)} == MSM(C, [1, 1]) = g^{1+2} = g^3.
    #[test]
    fun test_feldman_verification() {
        let a0 = group_bls12381_g1::scalar_from_u64(1); // f(0) = 1 = secret
        let a1 = group_bls12381_g1::scalar_from_u64(2);

        let g = g1_generator_point();

        // Commitment points: C0 = g^a0 = g, C1 = g^a1 = g^2
        let c0 = group_bls12381_g1::scale_point(&g, &a0);
        let c1 = group_bls12381_g1::scale_point(&g, &a1);

        // f(1) = a0 + a1*1 = 3. Verify g^3 == MSM([C0, C1], [1, 1])
        let one = group_bls12381_g1::scalar_from_u64(1);
        let f1 = group_bls12381_g1::scalar_from_u64(3);
        let lhs = group_bls12381_g1::scale_point(&g, &f1);
        let rhs = group_bls12381_g1::msm(vector[c0, c1], vector[one, one]);
        assert!(group_bls12381_g1::point_eq(&lhs, &rhs), 0);

        // f(2) = a0 + a1*2 = 5. Verify g^5 == MSM([C0, C1], [1, 2])
        let two = group_bls12381_g1::scalar_from_u64(2);
        let f2 = group_bls12381_g1::scalar_from_u64(5);
        let lhs2 = group_bls12381_g1::scale_point(&g, &f2);
        let rhs2 = group_bls12381_g1::msm(vector[c0, c1], vector[one, two]);
        assert!(group_bls12381_g1::point_eq(&lhs2, &rhs2), 1);
    }
}

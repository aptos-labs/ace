// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module ace::group_tests {
    use ace::group;
    use ace::group_bls12381_g1;
    use ace::group_bls12381_g2;
    use aptos_std::bcs_stream;

    // BLS12-381 G1 generator in compressed form (48 bytes, standard format).
    // First byte = 0x97 = 0x17 (x_coord MSB) | 0x80 (compressed flag).
    const G1_GENERATOR_COMPR: vector<u8> = x"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    fun g1_bcs_bytes(raw: vector<u8>): vector<u8> {
        // ULEB128(48) = 0x30
        let bcs_bytes = vector[0x30u8];
        bcs_bytes.append(raw);
        bcs_bytes
    }

    fun g1_generator_point(): group_bls12381_g1::PublicPoint {
        group_bls12381_g1::deserialize_public_point(
            &mut bcs_stream::new(g1_bcs_bytes(G1_GENERATOR_COMPR))
        )
    }

    fun g2_hashed_point(): group_bls12381_g2::PublicPoint {
        group_bls12381_g2::element_from_hash(&b"test-g2-base")
    }

    // ── group_bls12381_g1 scalar and point tests ─────────────────────────────

    // G^(3*4) == G^12 in Fr.
    #[test]
    fun test_scalar_mul_g1() {
        let a = group_bls12381_g1::scalar_from_u64(3);
        let b = group_bls12381_g1::scalar_from_u64(4);
        let c = group_bls12381_g1::scalar_mul(&a, &b);
        let twelve = group_bls12381_g1::scalar_from_u64(12);

        let g = g1_generator_point();
        let c_g = group_bls12381_g1::scale_point(&g, &c);
        let twelve_g = group_bls12381_g1::scale_point(&g, &twelve);
        assert!(group_bls12381_g1::point_eq(&c_g, &twelve_g), 0);
    }

    // MSM([G, G], [3, 9]) == 12*G.
    #[test]
    fun test_msm_g1() {
        let s3 = group_bls12381_g1::scalar_from_u64(3);
        let s9 = group_bls12381_g1::scalar_from_u64(9);
        let s12 = group_bls12381_g1::scalar_from_u64(12);

        let g = g1_generator_point();
        let msm_result = group_bls12381_g1::msm(vector[g, g], vector[s3, s9]);
        let twelve_g = group_bls12381_g1::scale_point(&g, &s12);
        assert!(group_bls12381_g1::point_eq(&msm_result, &twelve_g), 0);
    }

    // ── group_bls12381_g2 sibling tests ───────────────────────────────────────

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
}

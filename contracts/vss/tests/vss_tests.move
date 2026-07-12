// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module ace::vss_tests {
    use std::bcs;
    use std::option;
    use ace::vss;
    use ace::group;
    use ace::group_bls12381_g1;
    use ace::pedersen_polynomial_commitment;
    use ace::sigma_dlog_linear;
    use aptos_framework::randomness;
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

    // 3 domain points, all unopened -> all None.
    // Bytes: shares_to_reveal=[None,None,None].
    #[test]
    fun test_dc1_all_none() {
        let bytes = x"030000000000";
        let dc1 = vss::dc1_from_bytes_for_testing(bytes);
        assert!(vss::dc1_len(&dc1) == 3, 0);
        assert!(vss::dc1_is_none_at(&dc1, 0), 1);
        assert!(vss::dc1_is_none_at(&dc1, 1), 2);
        assert!(vss::dc1_is_none_at(&dc1, 2), 3);
    }

    #[test(framework = @0x1)]
    fun test_dc1_with_one_revealed(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = pedersen_polynomial_commitment::new_context(scheme);
        let prover_state = pedersen_polynomial_commitment::new_prover_state(
            vector[group::scalar_from_u64(scheme, 1), group::scalar_from_u64(scheme, 2)],
            vector[],
        );
        let _commitment = pedersen_polynomial_commitment::commit(&context, &mut prover_state, 3);
        let opening = pedersen_polynomial_commitment::open(&context, &prover_state, 2);

        let shares_to_reveal = vector[
            option::none(),
            option::none(),
            option::some(opening),
        ];
        let bytes = bcs::to_bytes(&shares_to_reveal);
        bytes.append(bcs::to_bytes(&vector<group::Element>[]));
        bytes.append(bcs::to_bytes(&vector<option::Option<sigma_dlog_linear::Proof>>[]));

        let dc1 = vss::dc1_from_bytes_for_testing(bytes);
        assert!(vss::dc1_len(&dc1) == 3, 0);
        assert!(vss::dc1_is_none_at(&dc1, 0), 1);
        assert!(vss::dc1_is_none_at(&dc1, 1), 2);
        assert!(vss::dc1_is_some_at(&dc1, 2), 3);
    }

    // ── Polynomial MSM checks via the abstract `group::*` API (G1 and G2) ───

    // Polynomial commitment arithmetic: for f(x) = a0 + a1*x with a0=1, a1=2,
    // commitment C = [g^1, g^2]. Verify g^{f(1)} == MSM(C, [1, 1]) = g^{1+2} = g^3.
    #[test]
    fun test_polynomial_msm_g1() {
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

    // Same MSM arithmetic driven through `group::*` over G2 to exercise the
    // VSS-relevant abstract operations against the second scheme.
    #[test]
    fun test_polynomial_msm_abstract_g2() {
        let scheme = group::scheme_bls12381_g2();
        let a0 = group::scalar_from_u64(scheme, 1);
        let a1 = group::scalar_from_u64(scheme, 2);

        let g = group::element_from_hash(scheme, &b"polynomial-msm-g2-base");
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
}

// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module ace::secret_usage_tests {
    use ace::group;
    use ace::secret_usage;
    use std::string;

    #[test]
    fun test_secret_usage_group_mapping() {
        assert!(
            secret_usage::usage_for_primitive(secret_usage::primitive_bls12381_g1_test_only())
                == secret_usage::usage_bls12381_g1_test_only(),
            0,
        );
        assert!(
            secret_usage::primitive_group_scheme(secret_usage::primitive_bls12381_g1_test_only())
                == group::scheme_bls12381_g1(),
            1,
        );
        assert!(
            secret_usage::usage_group_scheme(secret_usage::usage_bls12381_g1_test_only())
                == group::scheme_bls12381_g1(),
            2,
        );
        assert!(
            secret_usage::usage_group_scheme(secret_usage::usage_bls12381_g2_test_only())
                == group::scheme_bls12381_g2(),
            3,
        );
        assert!(
            secret_usage::usage_group_scheme(secret_usage::usage_bls12381_threshold_vrf())
                == group::scheme_bls12381_g2(),
            4,
        );
    }

    #[test]
    fun test_secret_usage_allows_same_group_multi_usage() {
        let usage = secret_usage::usage_bls12381_g2_test_only()
            | secret_usage::usage_bls12381_threshold_vrf();
        assert!(secret_usage::usage_group_scheme(usage) == group::scheme_bls12381_g2(), 10);
    }

    #[test]
    #[expected_failure]
    fun test_secret_usage_rejects_empty_usage() {
        secret_usage::usage_group_scheme(0);
    }

    #[test]
    #[expected_failure]
    fun test_secret_usage_rejects_unsupported_usage() {
        secret_usage::usage_group_scheme(secret_usage::supported_usage_mask() | 8);
    }

    #[test]
    #[expected_failure]
    fun test_secret_usage_rejects_cross_group_multi_usage() {
        secret_usage::usage_group_scheme(
            secret_usage::usage_bls12381_g1_test_only()
                | secret_usage::usage_bls12381_g2_test_only(),
        );
    }

    #[test]
    #[expected_failure]
    fun test_secret_usage_rejects_long_note() {
        let bytes = vector[];
        let i = 0;
        while (i <= secret_usage::max_note_bytes()) {
            bytes.push_back(0x61);
            i += 1;
        };
        secret_usage::new_request(
            secret_usage::usage_bls12381_threshold_vrf(),
            string::utf8(bytes),
        );
    }
}

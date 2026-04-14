// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Serde roundtrip tests for VSS typed structs.
// All golden byte constants are byte-identical to the constants in:
//   ts-sdk/tests/bls12381-fr-pcs.test.ts
//   ts-sdk/tests/vss-index-serde.test.ts
#[test_only]
module ace::vss_serde_tests {
    use aptos_std::bcs_stream;
    use ace::vss;
    use ace::vss_bls12381_fr;

    // ── Golden byte constants ─────────────────────────────────────────────────
    //
    // PCS_BATCH_OPENING_WRAPPER_GOLDEN (135 bytes):
    //   [u8 scheme=0]
    //   [02] pEvals len=2
    //     [20] [0100..00]  pEval[0] = Fr(1)
    //     [20] [0200..00]  pEval[1] = Fr(2)
    //   [02] rEvals len=2
    //     [20] [0300..00]  rEval[0] = Fr(3)
    //     [20] [0400..00]  rEval[1] = Fr(4)

    const DC1_GOLDEN: vector<u8> = x"000220010000000000000000000000000000000000000000000000000000000000000020020000000000000000000000000000000000000000000000000000000000000002200300000000000000000000000000000000000000000000000000000000000000200400000000000000000000000000000000000000000000000000000000000000";

    // PCS_COMMITMENT_WRAPPER_GOLDEN (51 bytes):
    //   [u8 scheme=0]
    //   [01] v_values len=1
    //   [30] 48-byte G1 generator (compressed)

    const PCS_COMMITMENT_GOLDEN: vector<u8> = x"00013097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    // DC0_GOLDEN: PCS_COMMITMENT_GOLDEN + [00] (0 share msgs) + [01] (Option::Some tag) + CIPHERTEXT_GOLDEN
    const DC0_GOLDEN: vector<u8> = x"00013097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb000100209664c19dd000f772c25ec65b4b4fccda7233a11b19c9c6ba9df43e55cd5ad06520f64f3d4419543d892e967726e831315da6dc52753b2db562e050e743fd38717b10f99cfbfd1a4a73d75e272be8a9682907206dffa55ba1c65e7ed865bd02b15bf58933139a4bd1022b94b99fe18ac7938d59";

    // ── DealerContribution1 roundtrip ────────────────────────────────────────

    #[test]
    fun test_dc1_roundtrip() {
        let dc1 = vss_bls12381_fr::parse_dealer_contribution_1(DC1_GOLDEN);
        assert!(vss_bls12381_fr::serialize_dealer_contribution_1(&dc1) == DC1_GOLDEN, 1);
    }

    #[test]
    #[expected_failure]
    fun test_dc1_trailing_bytes_rejected() {
        let bad = DC1_GOLDEN;
        bad.push_back(0x00);
        vss_bls12381_fr::parse_dealer_contribution_1(bad);
    }

    // ── DealerContribution0 parse ────────────────────────────────────────────
    // Full roundtrip deferred until ace::pke gains serializers for Ciphertext.

    #[test]
    fun test_dc0_golden() {
        let _dc0 = vss_bls12381_fr::parse_dealer_contribution_0(DC0_GOLDEN);
    }

    #[test]
    #[expected_failure]
    fun test_dc0_trailing_bytes_rejected() {
        let bad = DC0_GOLDEN;
        bad.push_back(0x00);
        vss_bls12381_fr::parse_dealer_contribution_0(bad);
    }

    // ── PcsCommitment roundtrip ──────────────────────────────────────────────

    #[test]
    fun test_pcs_commitment_roundtrip() {
        let stream = bcs_stream::new(PCS_COMMITMENT_GOLDEN);
        let commitment = vss::deserialize_pcs_commitment(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), 1);
        let scheme = vss::get_pcs_commitment_scheme(&commitment);
        let inner = vss::pcs_commitment_as_bls12381_fr(commitment);
        let serialized = vector[scheme];
        serialized.append(vss_bls12381_fr::serialize_pcs_commitment(&inner));
        assert!(serialized == PCS_COMMITMENT_GOLDEN, 2);
    }
}

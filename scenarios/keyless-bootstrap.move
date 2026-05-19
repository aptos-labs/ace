// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0
//
// One-shot Move script that installs the keyless test fixtures on a fresh
// `aptos node run-local-testnet`:
//
//   * RSA JWK for `iss="test.oidc.provider"`, `kid="test-rsa"` — the modulus
//     comes from `aptos-core/types/src/jwks/rsa/insecure_test_jwk.json`
//     (matches `SAMPLE_JWK`).
//   * Groth16 verifying key — the devnet test VK that `SAMPLE_PROOF` was
//     generated against. Compressed-byte values were extracted from
//     `aptos_types::keyless::circuit_constants::prepared_vk_for_testing()`
//     via `Groth16VerificationKey::from(&pvk)` (each field is the
//     ark-serialize compressed point bytes). See the top-of-file
//     regeneration notes in `scenarios/common/keyless-fixtures.ts`.
//   * Configuration knobs lifted to fit `SAMPLE_EXP_HORIZON_SECS`
//     (~31,710 years) and training-wheels signature disabled.
//
// Signer must be the localnet `core_resources` account (`0xA550C18`); its
// private key is at `~/.aptos/testnet/mint.key` after `aptos node
// run-local-testnet`. The script bounces through
// `aptos_governance::get_signer_testnet_only` to obtain the framework
// signer, then `force_end_epoch`s to make the buffered config + VK active.
script {
    use aptos_framework::aptos_governance;
    use aptos_framework::jwks;
    use aptos_framework::keyless_account;
    use std::option;
    use std::string::utf8;

    fun main(core_resources: &signer) {
        let fx = aptos_governance::get_signer_testnet_only(core_resources, @0x1);

        // 1. Install RSA JWK for "test.oidc.provider" / "test-rsa".
        let jwk = jwks::new_rsa_jwk(
            utf8(b"test-rsa"),
            utf8(b"RS256"),
            utf8(b"AQAB"),
            utf8(b"6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw"),
        );
        let patches = vector[
            jwks::new_patch_remove_all(),
            jwks::new_patch_upsert_jwk(b"test.oidc.provider", jwk),
        ];
        jwks::set_patches(&fx, patches);

        // 2. Install Groth16 VK matching SAMPLE_PROOF (devnet-groth16-keys @ 02e5675).
        //    Compressed-byte values from aptos-core's
        //    `prepared_vk_for_testing()` — see top-of-file regeneration notes.
        let vk = keyless_account::new_groth16_verification_key(
            x"e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2d",
            x"abb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789",
            x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
            x"6176de7d77e614e09ef5e8e19cbf785ffed405d6531cee13cd71a46e2b4ef30deb18f6976c172bdcd7ea8ab2b509991bb5ce34f9fbb42486b78aac62a894a480",
            vector[
                x"7e92d0c6818f2e51248cd1e8e82eb14521d990b0bb155ab0e3cf99b888bc5387",
                x"be1ad9f5fec081770956f846e1d0ea97219a3f6499acc33e1a67aef6d6e16898",
            ],
        );
        keyless_account::set_groth16_verification_key_for_next_epoch(&fx, vk);

        // 3. Lift `max_exp_horizon_secs` past SAMPLE_EXP_HORIZON_SECS
        //    (999_999_999_999) and clear the training-wheels pk so the worker
        //    can accept proofs that lack `training_wheels_signature`.
        keyless_account::update_max_exp_horizon_for_next_epoch(&fx, 1_000_000_000_000);
        keyless_account::update_training_wheels_for_next_epoch(&fx, option::none());

        // 4. Force the next reconfig so the buffered changes become active.
        aptos_governance::force_end_epoch(&fx);
    }
}

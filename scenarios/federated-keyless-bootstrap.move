// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0
//
// Framework-side fixtures for the federated-keyless scenario. Sister script
// to `keyless-bootstrap.move`; differs in one critical way:
//
//   * The system `PatchedJWKs` patch list is cleared (NOT populated with the
//     test RSA JWK). The test JWK is installed instead at `jwk_addr` by the
//     scenario itself via `0x1::jwks::update_federated_jwk_set` (a plain
//     `public entry fun` callable by any signer — no governance involved).
//
// Clearing the system list ensures the worker's federated-keyless verifier
// must consult `FederatedJWKs` at `jwk_addr` to find the JWK; if it only
// looked at `PatchedJWKs` (a regression) the proof would fail to verify.
//
// Pattern matches `federated_keyless_scenario` in
// `aptos-core/testsuite/smoke-test/src/keyless.rs` (rev 8ec3fb76).
//
// Groth16 VK + `Configuration` knobs are still framework-only operations and
// are installed identically to `keyless-bootstrap.move`.
//
// Signer must be the localnet `core_resources` account (`0xA550C18`); its
// private key is at `~/.aptos/testnet/mint.key`.
script {
    use aptos_framework::aptos_governance;
    use aptos_framework::jwks;
    use aptos_framework::keyless_account;
    use std::option;

    fun main(core_resources: &signer) {
        let fx = aptos_governance::get_signer_testnet_only(core_resources, @0x1);

        // 1. Clear all system JWK patches. The test JWK goes into
        //    FederatedJWKs at jwk_addr, installed by the scenario itself.
        jwks::set_patches(&fx, vector[]);

        // 2. Install Groth16 VK matching SAMPLE_PROOF (devnet-groth16-keys @ 02e5675).
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
        //    (999_999_999_999) and clear the training-wheels pk.
        keyless_account::update_max_exp_horizon_for_next_epoch(&fx, 1_000_000_000_000);
        keyless_account::update_training_wheels_for_next_epoch(&fx, option::none());

        // 4. Force the next reconfig so the buffered changes become active.
        aptos_governance::force_end_epoch(&fx);
    }
}

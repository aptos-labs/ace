// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Keyless test fixtures, ported from
 *   aptos-core/types/src/keyless/circuit_testcases.rs
 *
 * All values bind together — pepper, ephemeral keypair, blinder, JWT, expiry, and
 * Groth16 proof must be consistent or proof verification fails. Treat this file
 * as a single immutable bundle.
 *
 * Localnet prerequisites (assumed wired up out-of-band; see scenario header):
 *   - 0x1::jwks installs an RSA JWK under iss="test.oidc.provider", kid="test-rsa"
 *     with the modulus from aptos-core/types/src/jwks/rsa/insecure_test_jwk.json.
 *   - 0x1::keyless_account installs the Groth16 verifying key that matches
 *     SAMPLE_PROOF (devnet-groth16-keys @ 02e5675).
 *
 * To re-extract the bundle (one-time, when aptos-core test fixtures rotate):
 *   cd ~/repos/aptos-labs/aptos-core
 *   cargo run -p aptos-types --example dump_sample_keyless_fixtures
 *   # See worker-components/keyless-fixture-dumper for the dumper source (planned).
 */

// ── Identity ──────────────────────────────────────────────────────────────────

export const SAMPLE_ISS = 'test.oidc.provider';
export const SAMPLE_AUD = '407408718192.apps.googleusercontent.com';
export const SAMPLE_UID_KEY = 'sub';
export const SAMPLE_UID_VAL = '113990307082899718775';

// ── Pepper / blinder ──────────────────────────────────────────────────────────

// Pepper::from_number(76) → 31 bytes: [76, 0, 0, ..., 0]
export const SAMPLE_PEPPER_HEX = '4c' + '00'.repeat(30);

// First byte 42, rest zeros (31 bytes total).
export const SAMPLE_EPK_BLINDER_HEX = '2a' + '00'.repeat(30);

// ── Expiry ────────────────────────────────────────────────────────────────────

// 12/21/5490 — effectively never expires for test purposes.
export const SAMPLE_EXP_DATE_SECS = 111_111_111_111n;

// ~31,710 years.
export const SAMPLE_EXP_HORIZON_SECS = 999_999_999_999n;

// ── JWT ───────────────────────────────────────────────────────────────────────

// Header is well-known:
//   {"alg":"RS256","typ":"JWT","kid":"test-rsa"}
// Payload + signature depend on the ephemeral pubkey (via nonce), the issuer's
// RSA private key, and the IAT — we hardcode the resulting JWT string verbatim
// so the test does not need an RSA signer at runtime.
//
// TODO(keyless-fixtures): populate from the Rust dumper. The placeholder below
// is intentionally invalid so the test fails loudly until the fixture lands.
export const SAMPLE_JWT_PLACEHOLDER =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QtcnNhIn0.PLACEHOLDER.PLACEHOLDER';

// ── Ephemeral keypair ─────────────────────────────────────────────────────────

// Ed25519PrivateKey::generate_for_testing() — StdRng seeded with [0u8; 32].
// The exact 32 SK bytes are not derivable in TS without porting ChaCha20Rng, so
// we extract once and paste.
//
// TODO(keyless-fixtures): populate from the Rust dumper.
export const SAMPLE_EPHEMERAL_SK_HEX_PLACEHOLDER =
    '00'.repeat(32);

// ── Groth16 proof ─────────────────────────────────────────────────────────────
//
// Reference: SAMPLE_PROOF in aptos-core/types/src/keyless/circuit_testcases.rs
// Constructed from Groth16 (a ∈ G1, b ∈ G2, c ∈ G1) using bn254_circom encoding.

export const SAMPLE_PROOF_A_HEX =
    '3304cc0defd488d770af0439480ec24c8473b30dbcbfad9fdf99ca62256bd908';
export const SAMPLE_PROOF_B_HEX =
    '2f432b9459375ed2032bcb1ff3ccc1dd5d05a752d6956d2bb003f4e3b42d0b24' +
    '2cf4ab4d3dc8dc700ede17bbfeaddedd42033691e3d85ff8d6621663cb2e779a';
export const SAMPLE_PROOF_C_HEX =
    'd44ee2772f4b48fdb0dbd8d870d3fb4401cd3a28fbdde535e9c57bac9a263f9c';

// Public-input flavor matching SAMPLE_PROOF: uid_key="sub", no override aud,
// extra_field present ("family_name":"Straka").
export const SAMPLE_EXTRA_FIELD_KEY = 'family_name';
export const SAMPLE_EXTRA_FIELD = '"family_name":"Straka"';

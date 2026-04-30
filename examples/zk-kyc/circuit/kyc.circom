// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.0.0;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

//
// KYCProof — proves three things simultaneously:
//
//   1. The prover holds a credential (age) that was signed by the KYC provider
//      using EdDSA over Baby Jubjub with a Poseidon message hash.
//
//   2. The prover's age is 18 or older.
//
//   3. The proof is bound to a specific enc_pk (the ACE decryption request key).
//      enc_pk_p0/p1/p2 are public inputs — the Groth16 IC terms bind them to
//      the proof without any circuit constraints needed.
//
// Public output:
//   nullifier — Poseidon(sig_s), a unique fingerprint of the credential.
//               A real app records this on-chain after each decryption to
//               prevent the same credential from being used more than once.
//
// Public inputs  (visible to the on-chain verifier):
//   pk_provider_ax, pk_provider_ay  — KYC provider's Baby Jubjub public key
//   enc_pk_p0, enc_pk_p1, enc_pk_p2 — enc_pk packed little-endian into 3 scalars
//                                      (computed by the verifier from the raw enc_pk)
//
// Private inputs (known only to the prover, never revealed):
//   age           — numeric age (0–255)
//   sig_r8x, sig_r8y, sig_s  — EdDSA signature components
//
template KYCProof() {

    // ── Public inputs ──────────────────────────────────────────────────────────
    signal input pk_provider_ax;
    signal input pk_provider_ay;
    signal input enc_pk_p0;
    signal input enc_pk_p1;
    signal input enc_pk_p2;

    // ── Private inputs ─────────────────────────────────────────────────────────
    signal input age;
    signal input sig_r8x;
    signal input sig_r8y;
    signal input sig_s;

    // ── Public output ──────────────────────────────────────────────────────────
    signal output nullifier;

    // ── 1. EdDSA signature verification ───────────────────────────────────────
    component msg_hash = Poseidon(1);
    msg_hash.inputs[0] <== age;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax     <== pk_provider_ax;
    verifier.Ay     <== pk_provider_ay;
    verifier.R8x    <== sig_r8x;
    verifier.R8y    <== sig_r8y;
    verifier.S      <== sig_s;
    verifier.M      <== msg_hash.out;

    // ── 2. Age is 18 or older ─────────────────────────────────────────────────
    component ageCheck = GreaterEqThan(8);
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== 18;
    ageCheck.out === 1;

    // ── 3. Nullifier ──────────────────────────────────────────────────────────
    // Poseidon(sig_s) is a stable, unique fingerprint of this credential.
    // sig_s is deterministic (EdDSA is deterministic), so the same credential
    // always produces the same nullifier — allowing double-use detection.
    component null_hash = Poseidon(1);
    null_hash.inputs[0] <== sig_s;
    nullifier <== null_hash.out;

    // ── 4. enc_pk binding ─────────────────────────────────────────────────────
    // enc_pk_p0/p1/p2 are public inputs. The Groth16 IC terms in the pairing
    // equation bind them to the proof — no circuit constraints needed here.
}

component main {public [pk_provider_ax, pk_provider_ay, enc_pk_p0, enc_pk_p1, enc_pk_p2]} = KYCProof();

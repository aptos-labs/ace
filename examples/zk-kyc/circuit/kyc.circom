// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.0.0;

include "circomlib/circuits/eddsa.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

//
// KYCProof — proves three things simultaneously:
//
//   1. The prover holds a credential (jurisdiction code) that was signed by the
//      KYC provider using EdDSA over Baby Jubjub with a Poseidon message hash.
//
//   2. The jurisdiction is not in the sanctioned list
//      (codes 0–3: DPRK, Iran, Cuba, Syria).
//
//   3. The proof is bound to a specific enc_pk (the ACE decryption request key),
//      packed as three BN254 Fr field elements, preventing replay against a
//      different enc_pk.
//
// Public inputs  (visible to the on-chain verifier):
//   pk_provider_ax, pk_provider_ay  — KYC provider's Baby Jubjub public key
//   enc_pk_p0, enc_pk_p1, enc_pk_p2 — enc_pk packed little-endian into 3 scalars
//                                      p0 = bytes[0..30], p1 = bytes[31..61],
//                                      p2 = bytes[62..66]
//
// Private inputs (known only to the prover, never revealed):
//   jurisdiction  — numeric country code (0–255)
//   sig_r8x, sig_r8y, sig_s  — EdDSA signature components
//   enc_pk[67]   — raw enc_pk bytes
//
template KYCProof() {

    // ── Public inputs ──────────────────────────────────────────────────────────
    signal input pk_provider_ax;
    signal input pk_provider_ay;
    signal input enc_pk_p0;
    signal input enc_pk_p1;
    signal input enc_pk_p2;

    // ── Private inputs ─────────────────────────────────────────────────────────
    signal input jurisdiction;
    signal input sig_r8x;
    signal input sig_r8y;
    signal input sig_s;
    signal input enc_pk[67];

    // ── 1. EdDSA signature verification ───────────────────────────────────────
    // The message is Poseidon(jurisdiction). The KYC provider signs this message
    // with their Baby Jubjub private key using signPoseidon (circomlibjs).
    // EdDSAPoseidonVerifier internally computes the challenge as:
    //   H = Poseidon(R8x, R8y, Ax, Ay, M)
    // and checks B8*S == R8 + A*H on Baby Jubjub.

    component msg_hash = Poseidon(1);
    msg_hash.inputs[0] <== jurisdiction;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax     <== pk_provider_ax;
    verifier.Ay     <== pk_provider_ay;
    verifier.R8x    <== sig_r8x;
    verifier.R8y    <== sig_r8y;
    verifier.S      <== sig_s;
    verifier.M      <== msg_hash.out;

    // ── 2. Jurisdiction is not sanctioned ──────────────────────────────────────
    // Sanctioned codes: 0 = DPRK, 1 = Iran, 2 = Cuba, 3 = Syria.
    // Constraint: product of (1 - IsEqual(jurisdiction, i)) for i in 0..3 must be 1.

    component eq[4];
    for (var i = 0; i < 4; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== jurisdiction;
        eq[i].in[1] <== i;
    }
    signal ns01 <== (1 - eq[0].out) * (1 - eq[1].out);
    signal ns23 <== (1 - eq[2].out) * (1 - eq[3].out);
    signal not_sanctioned <== ns01 * ns23;
    not_sanctioned === 1;

    // ── 3. enc_pk packing ──────────────────────────────────────────────────────
    // Pack enc_pk[67] bytes into three BN254 Fr scalars (little-endian).
    // Each byte is treated as a field element and summed with powers of 256.
    // Since max(p0) = 255*(256^31-1)/255 = 256^31-1 = 2^248-1 < r (BN254 prime),
    // no field wrapping occurs and the packing is injective.
    //
    // p0 = enc_pk[0] + enc_pk[1]*256 + ... + enc_pk[30]*256^30
    // p1 = enc_pk[31] + enc_pk[32]*256 + ... + enc_pk[61]*256^30
    // p2 = enc_pk[62] + enc_pk[63]*256 + enc_pk[64]*256^2
    //      + enc_pk[65]*256^3 + enc_pk[66]*256^4

    var acc0 = 0;
    var acc1 = 0;
    var acc2 = 0;
    var c = 1;

    for (var i = 0; i < 31; i++) {
        acc0 += enc_pk[i] * c;
        acc1 += enc_pk[31 + i] * c;
        c *= 256;
    }
    for (var i = 0; i < 5; i++) {
        if (i == 0) { c = 1; }
        acc2 += enc_pk[62 + i] * c;
        c *= 256;
    }

    signal p0_computed <== acc0;
    signal p1_computed <== acc1;
    signal p2_computed <== acc2;

    p0_computed === enc_pk_p0;
    p1_computed === enc_pk_p1;
    p2_computed === enc_pk_p2;
}

component main {public [pk_provider_ax, pk_provider_ay, enc_pk_p0, enc_pk_p1, enc_pk_p2]} = KYCProof();

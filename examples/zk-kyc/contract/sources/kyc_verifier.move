// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// On-chain Groth16 verifier for the ZK-KYC circuit.
///
/// The admin deploys this module once, then calls `initialize` with:
///   - The Groth16 verification key (from circuit/vk.json after setup.sh).
///   - The KYC provider's Baby JubJub public key.
///
/// ACE workers call `check_acl(label, enc_pk, payload)` as a view function
/// before releasing a decryption key share.  `payload` is a 256-byte Groth16
/// proof (pi_a 64B || pi_b 128B || pi_c 64B).
///
/// The verifier checks that the proof simultaneously witnesses:
///   1. A valid EdDSA-Poseidon signature from the KYC provider over a
///      jurisdiction code.
///   2. The jurisdiction is NOT in the sanctioned list (DPRK/Iran/Cuba/Syria).
///   3. The proof is bound to the caller's `enc_pk` — preventing replay against
///      a different key.
///
/// Binding is achieved without an on-chain hash: the circuit packs enc_pk[67]
/// into 3 BN254 Fr scalars (same polynomial-evaluation scheme on both sides).
module admin::kyc_verifier {
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::crypto_algebra::{
        Element, deserialize, from_u64, multi_scalar_mul, pairing, add, zero, eq,
    };
    use aptos_std::bn254_algebra::{
        G1, G2, Gt, Fr,
        FormatG1Uncompr, FormatG2Uncompr, FormatFrLsb,
    };

    const E_ONLY_ADMIN: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;

    // proof layout: G1(64) + G2(128) + G1(64) = 256 bytes
    const PROOF_LEN: u64 = 256;
    // Ristretto255 compressed point = 67 bytes
    const ENC_PK_LEN: u64 = 67;
    // IC count = 1 (constant) + 5 (public inputs) = 6
    const IC_COUNT: u64 = 6;

    struct VerificationKey has key {
        // Groth16 VK stored as raw bytes; deserialized on every check_acl call.
        // G1 uncompressed = x_le32 || y_le32 (64 bytes)
        // G2 uncompressed = x0_le32 || x1_le32 || y0_le32 || y1_le32 (128 bytes)
        vk_alpha_g1: vector<u8>,   // 64 bytes
        vk_beta_g2:  vector<u8>,   // 128 bytes
        vk_gamma_g2: vector<u8>,   // 128 bytes
        vk_delta_g2: vector<u8>,   // 128 bytes
        vk_ic:       vector<u8>,   // 6 * 64 = 384 bytes (IC[0..5])
        // KYC provider's Baby JubJub public key (BN254 Fr, 32 bytes LE each)
        pk_provider_ax: vector<u8>, // 32 bytes
        pk_provider_ay: vector<u8>, // 32 bytes
    }

    /// Store the VK and provider public key on-chain.
    ///
    /// All byte arguments use little-endian BN254 field-element encoding:
    ///   G1 (64 B)  : x_le32 || y_le32
    ///   G2 (128 B) : x0_le32 || x1_le32 || y0_le32 || y1_le32
    ///   Fr (32 B)  : v_le32
    public entry fun initialize(
        admin: &signer,
        vk_alpha_g1:  vector<u8>,
        vk_beta_g2:   vector<u8>,
        vk_gamma_g2:  vector<u8>,
        vk_delta_g2:  vector<u8>,
        vk_ic:        vector<u8>,
        pk_provider_ax: vector<u8>,
        pk_provider_ay: vector<u8>,
    ) {
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN));
        assert!(!exists<VerificationKey>(@admin), error::already_exists(E_ALREADY_INITIALIZED));
        move_to(admin, VerificationKey {
            vk_alpha_g1,
            vk_beta_g2,
            vk_gamma_g2,
            vk_delta_g2,
            vk_ic,
            pk_provider_ax,
            pk_provider_ay,
        });
    }

    /// ACE hook: returns true iff payload is a valid Groth16 proof that the
    /// prover holds a KYC credential for a non-sanctioned jurisdiction,
    /// bound to enc_pk.  label is verified by ACE itself and is ignored here.
    #[view]
    public fun check_acl(
        _label: vector<u8>,
        enc_pk:  vector<u8>,
        payload: vector<u8>,
    ): bool acquires VerificationKey {
        if (!exists<VerificationKey>(@admin)) return false;
        if (vector::length(&payload) != PROOF_LEN)  return false;
        if (vector::length(&enc_pk)  != ENC_PK_LEN) return false;

        let vk = borrow_global<VerificationKey>(@admin);

        // ── Deserialise proof ─────────────────────────────────────────────────
        let opt_a = deserialize<G1, FormatG1Uncompr>(&slice(&payload, 0, 64));
        if (option::is_none(&opt_a)) return false;
        let proof_a = option::extract(&mut opt_a);

        let opt_b = deserialize<G2, FormatG2Uncompr>(&slice(&payload, 64, 192));
        if (option::is_none(&opt_b)) return false;
        let proof_b = option::extract(&mut opt_b);

        let opt_c = deserialize<G1, FormatG1Uncompr>(&slice(&payload, 192, 256));
        if (option::is_none(&opt_c)) return false;
        let proof_c = option::extract(&mut opt_c);

        // ── Deserialise VK ───────────────────────────────────────────────────
        let opt_alpha = deserialize<G1, FormatG1Uncompr>(&vk.vk_alpha_g1);
        if (option::is_none(&opt_alpha)) return false;
        let vk_alpha = option::extract(&mut opt_alpha);

        let opt_beta = deserialize<G2, FormatG2Uncompr>(&vk.vk_beta_g2);
        if (option::is_none(&opt_beta)) return false;
        let vk_beta = option::extract(&mut opt_beta);

        let opt_gamma = deserialize<G2, FormatG2Uncompr>(&vk.vk_gamma_g2);
        if (option::is_none(&opt_gamma)) return false;
        let vk_gamma = option::extract(&mut opt_gamma);

        let opt_delta = deserialize<G2, FormatG2Uncompr>(&vk.vk_delta_g2);
        if (option::is_none(&opt_delta)) return false;
        let vk_delta = option::extract(&mut opt_delta);

        // IC: IC_COUNT × 64 bytes
        let ic: vector<Element<G1>> = vector::empty();
        let i = 0u64;
        while (i < IC_COUNT) {
            let opt_ic = deserialize<G1, FormatG1Uncompr>(&slice(&vk.vk_ic, i * 64, (i + 1) * 64));
            if (option::is_none(&opt_ic)) return false;
            vector::push_back(&mut ic, option::extract(&mut opt_ic));
            i = i + 1;
        };

        // ── Public inputs: [pk_ax, pk_ay, p0, p1, p2] ────────────────────────
        let opt_ax = deserialize<Fr, FormatFrLsb>(&vk.pk_provider_ax);
        if (option::is_none(&opt_ax)) return false;

        let opt_ay = deserialize<Fr, FormatFrLsb>(&vk.pk_provider_ay);
        if (option::is_none(&opt_ay)) return false;

        let (opt_p0, opt_p1, opt_p2) = pack_enc_pk_to_fr(&enc_pk);
        if (option::is_none(&opt_p0) || option::is_none(&opt_p1) || option::is_none(&opt_p2)) {
            return false
        };

        let public_inputs = vector[
            option::extract(&mut opt_ax),
            option::extract(&mut opt_ay),
            option::extract(&mut opt_p0),
            option::extract(&mut opt_p1),
            option::extract(&mut opt_p2),
        ];

        // ── Groth16 pairing check ────────────────────────────────────────────
        // e(A, B) == e(α, β) · e(Σ IC_i·s_i, γ) · e(C, δ)
        // where s = [1, pk_ax, pk_ay, p0, p1, p2]
        let left = pairing<G1, G2, Gt>(&proof_a, &proof_b);

        let scalars = vector[from_u64<Fr>(1)];
        vector::append(&mut scalars, public_inputs);
        let vk_x = multi_scalar_mul(&ic, &scalars);

        let right = zero<Gt>();
        let right = add(&right, &pairing<G1, G2, Gt>(&vk_alpha, &vk_beta));
        let right = add(&right, &pairing<G1, G2, Gt>(&vk_x, &vk_gamma));
        let right = add(&right, &pairing<G1, G2, Gt>(&proof_c, &vk_delta));

        eq(&left, &right)
    }

    // Pack enc_pk[67] into three BN254 Fr scalars.
    // Mirrors the circuit's enc_pk packing constraints exactly:
    //   p0 = enc_pk[0..30]  little-endian polynomial evaluation
    //   p1 = enc_pk[31..61] little-endian polynomial evaluation
    //   p2 = enc_pk[62..66] little-endian polynomial evaluation
    fun pack_enc_pk_to_fr(enc_pk: &vector<u8>)
        : (option::Option<Element<Fr>>, option::Option<Element<Fr>>, option::Option<Element<Fr>>)
    {
        let p0: u256 = 0;
        let p1: u256 = 0;
        let p2: u256 = 0;
        let c:  u256 = 1;
        let i = 0u64;
        while (i < 31) {
            p0 = p0 + (*vector::borrow(enc_pk, i)      as u256) * c;
            p1 = p1 + (*vector::borrow(enc_pk, 31 + i) as u256) * c;
            c = c * 256;
            i = i + 1;
        };
        c = 1;
        let i = 0u64;
        while (i < 5) {
            p2 = p2 + (*vector::borrow(enc_pk, 62 + i) as u256) * c;
            c = c * 256;
            i = i + 1;
        };
        (fr_from_u256(p0), fr_from_u256(p1), fr_from_u256(p2))
    }

    fun fr_from_u256(v: u256): option::Option<Element<Fr>> {
        deserialize<Fr, FormatFrLsb>(&bcs::to_bytes<u256>(&v))
    }

    // Copy bytes [from, to) from a vector.
    fun slice(v: &vector<u8>, from: u64, to: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i = from;
        while (i < to) {
            vector::push_back(&mut out, *vector::borrow(v, i));
            i = i + 1;
        };
        out
    }
}

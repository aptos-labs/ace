// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Anonymous member-only ACE hook.
///
/// The organization stores a Merkle root of member commitments. A decrypter
/// proves in zero knowledge that they know one member secret whose commitment
/// is under that root, without revealing which member they are.
///
/// ACE workers call `check_acl(label, enc_pk, payload)` before releasing an IDK
/// share. `payload` is 288 bytes:
///   proof (256B): pi_a 64B || pi_b 128B || pi_c 64B
    ///   nullifier (32B): Poseidon(member_secret, label_fr, enc_pk_p0,
    ///                    enc_pk_p1, enc_pk_p2) as a little-endian BN254 Fr scalar
module admin::member_vault {
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::bn254_algebra::{
        G1, G2, Gt, Fr,
        FormatG1Uncompr, FormatG2Uncompr, FormatFrLsb,
    };
    use aptos_std::crypto_algebra::{
        Element, add, deserialize, eq, from_u64, multi_scalar_mul, pairing, zero,
    };

    const E_ONLY_ADMIN: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;

    // payload layout: G1(64) + G2(128) + G1(64) + Fr(32) = 288 bytes
    const PAYLOAD_LEN: u64 = 288;
    // The demo packs enc_pk into 3 field elements: three chunks of up to 30
    // bytes, each with a one-byte length suffix.
    const MAX_ENC_PK_LEN: u64 = 90;
    const FIELD_CHUNK_LEN: u64 = 30;
    // We pack up to 30 label bytes plus a 1-byte length suffix into one Fr.
    const MAX_LABEL_LEN: u64 = 30;
    // IC count = 1 constant + 1 nullifier output + 5 public inputs = 7
    const IC_COUNT: u64 = 7;

    struct VerificationKey has key {
        vk_alpha_g1: vector<u8>, // 64 bytes
        vk_beta_g2:  vector<u8>, // 128 bytes
        vk_gamma_g2: vector<u8>, // 128 bytes
        vk_delta_g2: vector<u8>, // 128 bytes
        vk_ic:       vector<u8>, // 7 * 64 bytes
        root_fr:     vector<u8>, // 32-byte little-endian BN254 Fr
    }

    public entry fun initialize(
        admin: &signer,
        vk_alpha_g1: vector<u8>,
        vk_beta_g2: vector<u8>,
        vk_gamma_g2: vector<u8>,
        vk_delta_g2: vector<u8>,
        vk_ic: vector<u8>,
        root_fr: vector<u8>,
    ) {
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN));
        assert!(!exists<VerificationKey>(@admin), error::already_exists(E_ALREADY_INITIALIZED));
        move_to(admin, VerificationKey {
            vk_alpha_g1,
            vk_beta_g2,
            vk_gamma_g2,
            vk_delta_g2,
            vk_ic,
            root_fr,
        });
    }

    /// Rotate the member set root. A production app would put governance around
    /// this entry function; the demo keeps it admin-only.
    public entry fun update_root(admin: &signer, root_fr: vector<u8>) acquires VerificationKey {
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN));
        borrow_global_mut<VerificationKey>(@admin).root_fr = root_fr;
    }

    #[view]
    public fun current_root(): vector<u8> acquires VerificationKey {
        if (!exists<VerificationKey>(@admin)) return vector::empty<u8>();
        borrow_global<VerificationKey>(@admin).root_fr
    }

    // ACE hook: returns true iff payload is a valid membership proof for the
    // current root, bound to this label and this request's enc_pk.
    #[view]
    public fun check_acl(
        label: vector<u8>,
        enc_pk: vector<u8>,
        payload: vector<u8>,
    ): bool acquires VerificationKey {
        if (!exists<VerificationKey>(@admin)) return false;
        if (vector::length(&payload) != PAYLOAD_LEN) return false;
        if (vector::length(&enc_pk) == 0) return false;
        if (vector::length(&enc_pk) > MAX_ENC_PK_LEN) return false;
        if (vector::length(&label) > MAX_LABEL_LEN) return false;

        let vk = borrow_global<VerificationKey>(@admin);

        let opt_a = deserialize<G1, FormatG1Uncompr>(&slice(&payload, 0, 64));
        if (option::is_none(&opt_a)) return false;
        let proof_a = option::extract(&mut opt_a);

        let opt_b = deserialize<G2, FormatG2Uncompr>(&slice(&payload, 64, 192));
        if (option::is_none(&opt_b)) return false;
        let proof_b = option::extract(&mut opt_b);

        let opt_c = deserialize<G1, FormatG1Uncompr>(&slice(&payload, 192, 256));
        if (option::is_none(&opt_c)) return false;
        let proof_c = option::extract(&mut opt_c);

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

        let ic: vector<Element<G1>> = vector::empty();
        let i = 0u64;
        while (i < IC_COUNT) {
            let opt_ic = deserialize<G1, FormatG1Uncompr>(&slice(&vk.vk_ic, i * 64, (i + 1) * 64));
            if (option::is_none(&opt_ic)) return false;
            vector::push_back(&mut ic, option::extract(&mut opt_ic));
            i = i + 1;
        };

        let opt_nullifier = deserialize<Fr, FormatFrLsb>(&slice(&payload, 256, 288));
        if (option::is_none(&opt_nullifier)) return false;

        let opt_root = deserialize<Fr, FormatFrLsb>(&vk.root_fr);
        if (option::is_none(&opt_root)) return false;

        let opt_label = label_to_fr(&label);
        if (option::is_none(&opt_label)) return false;

        let (opt_p0, opt_p1, opt_p2) = pack_enc_pk_to_fr(&enc_pk);
        if (option::is_none(&opt_p0) || option::is_none(&opt_p1) || option::is_none(&opt_p2)) {
            return false
        };

        // s = [1, nullifier, root, label_fr, p0, p1, p2]
        let public_inputs = vector[
            option::extract(&mut opt_nullifier),
            option::extract(&mut opt_root),
            option::extract(&mut opt_label),
            option::extract(&mut opt_p0),
            option::extract(&mut opt_p1),
            option::extract(&mut opt_p2),
        ];

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

    fun label_to_fr(label: &vector<u8>): option::Option<Element<Fr>> {
        let v: u256 = 0;
        let c: u256 = 1;
        let i = 0u64;
        let len = vector::length(label);
        while (i < len) {
            v = v + (*vector::borrow(label, i) as u256) * c;
            c = c * 256;
            i = i + 1;
        };
        v = v + (len as u256) * c;
        fr_from_u256(v)
    }

    fun pack_enc_pk_to_fr(enc_pk: &vector<u8>)
        : (option::Option<Element<Fr>>, option::Option<Element<Fr>>, option::Option<Element<Fr>>)
    {
        (
            pack_byte_chunk_to_fr(enc_pk, 0),
            pack_byte_chunk_to_fr(enc_pk, FIELD_CHUNK_LEN),
            pack_byte_chunk_to_fr(enc_pk, FIELD_CHUNK_LEN * 2),
        )
    }

    fun pack_byte_chunk_to_fr(bytes: &vector<u8>, start: u64): option::Option<Element<Fr>> {
        let total_len = vector::length(bytes);
        let chunk_len = if (start >= total_len) {
            0
        } else if (total_len - start > FIELD_CHUNK_LEN) {
            FIELD_CHUNK_LEN
        } else {
            total_len - start
        };

        let v: u256 = 0;
        let c: u256 = 1;
        let i = 0u64;
        while (i < chunk_len) {
            v = v + (*vector::borrow(bytes, start + i) as u256) * c;
            c = c * 256;
            i = i + 1;
        };
        v = v + (chunk_len as u256) * c;
        fr_from_u256(v)
    }

    fun fr_from_u256(v: u256): option::Option<Element<Fr>> {
        deserialize<Fr, FormatFrLsb>(&bcs::to_bytes<u256>(&v))
    }

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

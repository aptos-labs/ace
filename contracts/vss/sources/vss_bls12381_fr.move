// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// BLS12-381 Fr VSS variant — concrete types and serde.
/// Mirrors ts-sdk/src/vss/bls12381-fr.ts.
/// BCS wire format is byte-identical with the TypeScript implementation.
///
/// Scheme-specific structs, serde, and accessors live here.
/// The abstract outer layer lives in ace::vss.
module ace::vss_bls12381_fr {
    use std::option::{Self, Option};
    use aptos_std::bcs_stream::{Self, BCSStream};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bls12381_algebra::{G1, FormatG1Compr, Fr, FormatFrLsb};
    use ace::pke::{Self, Ciphertext};

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID: u64 = 1;

    // ── Constants ────────────────────────────────────────────────────────────

    const G1_COMPRESSED_BYTES: u64 = 48;
    const FR_SCALAR_BYTES: u64 = 32;

    /// Scheme byte for this variant (matches SCHEME_BLS12381FR in ace::vss).
    const SCHEME: u8 = 0;

    // ── Types — no scheme field; abstract layer owns the scheme byte ─────────

    /// Wire (no scheme prefix): [uleb128 n] { [uleb128(48)] [48-byte G1] } × n
    struct PcsCommitment has drop {
        v_values: vector<Element<G1>>,
    }

    /// Wire (no scheme prefix): [uleb128(32)] [32-byte Fr LE] [uleb128(32)] [32-byte Fr LE]
    struct PcsOpening has drop {
        p_eval: Element<Fr>,
        r_eval: Element<Fr>,
    }

    /// Wire (no scheme prefix):
    ///   [uleb128 n] { [uleb128(32)] [32-byte Fr LE] } × n   ← pEvals
    ///   [uleb128 m] { [uleb128(32)] [32-byte Fr LE] } × m   ← rEvals
    struct PcsBatchOpening has drop {
        p_evals: vector<Element<Fr>>,
        r_evals: vector<Element<Fr>>,
    }

    struct DealerContribution0 has drop {
        pcs_commitment: PcsCommitment,
        private_share_messages: vector<Ciphertext>,
        dealer_state: Option<Ciphertext>,
    }

    struct DealerContribution1 has drop {
        pcs_batch_opening: PcsBatchOpening,
    }

    // ── Internal serde helpers ────────────────────────────────────────────────

    fun deserialize_bytes_field(stream: &mut BCSStream): vector<u8> {
        bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s))
    }

    fun deserialize_g1_point(stream: &mut BCSStream): Element<G1> {
        let bytes = deserialize_bytes_field(stream);
        assert!(bytes.length() == G1_COMPRESSED_BYTES, E_INVALID);
        let opt = crypto_algebra::deserialize<G1, FormatG1Compr>(&bytes);
        assert!(opt.is_some(), E_INVALID);
        opt.destroy_some()
    }

    fun deserialize_fr_scalar(stream: &mut BCSStream): Element<Fr> {
        let bytes = deserialize_bytes_field(stream);
        assert!(bytes.length() == FR_SCALAR_BYTES, E_INVALID);
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(&bytes);
        assert!(opt.is_some(), E_INVALID);
        opt.destroy_some()
    }

    /// Encode n as ULEB128 (recursive, no loop variable mutation needed).
    fun uleb128(n: u64): vector<u8> {
        let byte = (n & 0x7f) as u8;
        let rest = n >> 7;
        if (rest == 0) {
            vector[byte]
        } else {
            let result = vector[byte | 0x80u8];
            result.append(uleb128(rest));
            result
        }
    }

    /// Serialize raw bytes as a BCS bytes field: [uleb128(len)][bytes].
    fun serialize_bytes_field(bytes: vector<u8>): vector<u8> {
        let result = uleb128(bytes.length() as u64);
        result.append(bytes);
        result
    }

    // ── Deserializers — NO leading scheme byte ────────────────────────────────
    //
    // The abstract layer (ace::vss) reads and validates the scheme byte before
    // calling these. DealerContribution0/1 parse functions below handle the
    // scheme byte themselves for standalone use.

    /// Parse a `PcsCommitment` from a BCS stream (no leading scheme byte).
    public fun deserialize_pcs_commitment(stream: &mut BCSStream): PcsCommitment {
        let v_values = bcs_stream::deserialize_vector(stream, |s| deserialize_g1_point(s));
        PcsCommitment { v_values }
    }

    /// Parse a `PcsOpening` from a BCS stream (no leading scheme byte).
    public fun deserialize_pcs_opening(stream: &mut BCSStream): PcsOpening {
        let p_eval = deserialize_fr_scalar(stream);
        let r_eval = deserialize_fr_scalar(stream);
        PcsOpening { p_eval, r_eval }
    }

    /// Parse a `PcsBatchOpening` from a BCS stream (no leading scheme byte).
    public fun deserialize_pcs_batch_opening(stream: &mut BCSStream): PcsBatchOpening {
        let p_evals = bcs_stream::deserialize_vector(stream, |s| deserialize_fr_scalar(s));
        let r_evals = bcs_stream::deserialize_vector(stream, |s| deserialize_fr_scalar(s));
        assert!(p_evals.length() == r_evals.length(), E_INVALID);
        PcsBatchOpening { p_evals, r_evals }
    }

    /// Parse a `DealerContribution0` from a BCS stream (no leading scheme byte).
    public fun deserialize_dealer_contribution_0(stream: &mut BCSStream): DealerContribution0 {
        let pcs_commitment = deserialize_pcs_commitment(stream);
        let private_share_messages = bcs_stream::deserialize_vector(stream, |s| pke::deserialize_ciphertext(s));
        let tag = bcs_stream::deserialize_u8(stream);
        let dealer_state = if (tag == 1) {
            option::some(pke::deserialize_ciphertext(stream))
        } else if (tag == 0) {
            option::none()
        } else {
            abort E_INVALID
        };
        DealerContribution0 { pcs_commitment, private_share_messages, dealer_state }
    }

    /// Parse a `DealerContribution1` from a BCS stream (no leading scheme byte).
    public fun deserialize_dealer_contribution_1(stream: &mut BCSStream): DealerContribution1 {
        let pcs_batch_opening = deserialize_pcs_batch_opening(stream);
        DealerContribution1 { pcs_batch_opening }
    }

    // ── Serializers — NO leading scheme byte ─────────────────────────────────

    /// Serialize a `PcsCommitment` body (no scheme byte).
    public fun serialize_pcs_commitment(c: &PcsCommitment): vector<u8> {
        let n = c.v_values.length();
        let bytes = uleb128(n as u64);
        for (i in 0..n) {
            bytes.append(serialize_bytes_field(
                crypto_algebra::serialize<G1, FormatG1Compr>(&c.v_values[i])
            ));
        };
        bytes
    }

    /// Serialize a `PcsOpening` body (no scheme byte).
    public fun serialize_pcs_opening(o: &PcsOpening): vector<u8> {
        let bytes = serialize_bytes_field(crypto_algebra::serialize<Fr, FormatFrLsb>(&o.p_eval));
        bytes.append(serialize_bytes_field(crypto_algebra::serialize<Fr, FormatFrLsb>(&o.r_eval)));
        bytes
    }

    /// Serialize a `PcsBatchOpening` body (no scheme byte).
    public fun serialize_pcs_batch_opening(o: &PcsBatchOpening): vector<u8> {
        let n = o.p_evals.length();
        let bytes = uleb128(n as u64);
        for (i in 0..n) {
            bytes.append(serialize_bytes_field(
                crypto_algebra::serialize<Fr, FormatFrLsb>(&o.p_evals[i])
            ));
        };
        bytes.append(uleb128(o.r_evals.length() as u64));
        for (i in 0..o.r_evals.length()) {
            bytes.append(serialize_bytes_field(
                crypto_algebra::serialize<Fr, FormatFrLsb>(&o.r_evals[i])
            ));
        };
        bytes
    }

    // ── Parse functions — full payload including scheme byte ─────────────────

    /// Parse and validate a `DealerContribution0` from raw BCS bytes.
    /// Reads and validates the leading scheme byte (first byte of the PcsCommitment).
    public fun parse_dealer_contribution_0(payload: vector<u8>): DealerContribution0 {
        let stream = bcs_stream::new(payload);
        let scheme = bcs_stream::deserialize_u8(&mut stream);
        assert!(scheme == SCHEME, E_INVALID);
        let dc0 = deserialize_dealer_contribution_0(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), E_INVALID);
        dc0
    }

    /// Parse and validate a `DealerContribution1` from raw BCS bytes.
    /// Reads and validates the leading scheme byte (first byte of the PcsBatchOpening).
    public fun parse_dealer_contribution_1(payload: vector<u8>): DealerContribution1 {
        let stream = bcs_stream::new(payload);
        let scheme = bcs_stream::deserialize_u8(&mut stream);
        assert!(scheme == SCHEME, E_INVALID);
        let dc1 = deserialize_dealer_contribution_1(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), E_INVALID);
        dc1
    }

    // ── Serializers — full payload including scheme byte ─────────────────────

    /// Serialize a `DealerContribution1` to BCS bytes (includes leading scheme byte).
    public fun serialize_dealer_contribution_1(dc1: &DealerContribution1): vector<u8> {
        let bytes = vector[SCHEME];
        bytes.append(serialize_pcs_batch_opening(&dc1.pcs_batch_opening));
        bytes
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public fun pcs_commitment_v_values(c: &PcsCommitment): &vector<Element<G1>> {
        &c.v_values
    }

    public fun pcs_opening_p_eval(o: &PcsOpening): &Element<Fr> {
        &o.p_eval
    }

    public fun pcs_opening_r_eval(o: &PcsOpening): &Element<Fr> {
        &o.r_eval
    }

    public fun pcs_batch_opening_p_evals(o: &PcsBatchOpening): &vector<Element<Fr>> {
        &o.p_evals
    }

    public fun pcs_batch_opening_r_evals(o: &PcsBatchOpening): &vector<Element<Fr>> {
        &o.r_evals
    }

    public fun dc0_pcs_commitment(dc0: &DealerContribution0): &PcsCommitment {
        &dc0.pcs_commitment
    }

    public fun dc0_private_share_messages(dc0: &DealerContribution0): &vector<Ciphertext> {
        &dc0.private_share_messages
    }

    public fun dc0_dealer_state(dc0: &DealerContribution0): &Option<Ciphertext> {
        &dc0.dealer_state
    }

    public fun dc1_pcs_batch_opening(dc1: &DealerContribution1): &PcsBatchOpening {
        &dc1.pcs_batch_opening
    }
}

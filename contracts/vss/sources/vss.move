// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// VSS abstract layer — scheme-dispatching enums and on-chain session management.
/// Mirrors ts-sdk/src/vss/index.ts.
///
/// Each enum currently has one variant (BLS12-381 Fr = scheme 0).
/// Adding a new scheme is an additive change: add a variant here and a sibling module.
/// Scheme-specific types and serde live in ace::vss_bls12381_fr.
module ace::vss {
    use std::bcs;
    use std::error;
    use std::signer::address_of;
    use std::vector::{range};
    use aptos_framework::object;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::worker_config;
    use ace::vss_bls12381_fr;

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID_CONTRIBUTION: u64 = 16;
    const E_ALREADY_CONTRIBUTED: u64 = 15;
    const E_ONLT_DEALER_CAN_DO_THIS: u64 = 18;
    const E_ESCROW_TOO_LARGE: u64 = 19;
    const E_NOT_IN_PROGRESS: u64 = 20;
    const E_INVALID_DEALER: u64 = 21;
    const E_INVALID_RECIPIENT: u64 = 22;
    const E_INVALID_THRESHOLD: u64 = 23;
    const E_UNSUPORTED_SECRET_SCHEME: u64 = 24;
    const E_RECIPIENT_NOT_FOUND: u64 = 25;
    const E_TOO_EARLY_TO_OPEN: u64 = 26;

    // ── Protocol constants ───────────────────────────────────────────────────

    const ACK_WINDOW_MICROS: u64 = 5_000_000; // 5 seconds for localnet

    const SECRET_SCHEME__BLS12381G1: u8 = 0;
    const SECRET_SCHEME__BLS12381G2: u8 = 1;

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__SUCCESS: u8 = 2;
    const STATE__FAILED: u8 = 3;

    // ── Scheme constants ─────────────────────────────────────────────────────

    const SCHEME_BLS12381FR: u8 = 0;

    // ── On-chain session state ────────────────────────────────────────────────

    struct Session has key {
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        secret_scheme: u8,
        state_code: u8,
        deal_time_micros: u64,
        dealer_contribution_0: vector<u8>,
        share_holder_acks: vector<bool>,
        dealer_contribution_1: vector<u8>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    // ── Abstract wrapper enums ────────────────────────────────────────────────
    //
    // Only types that have a `scheme` field in ts-sdk/src/vss/index.ts are enums here.
    // DealerContribution0 and DealerContribution1 have no scheme field and live only in
    // ace::vss_bls12381_fr.

    /// Wire: [u8 scheme] [inner PcsCommitment bytes]
    enum PcsCommitment has drop {
        Bls12381Fr(vss_bls12381_fr::PcsCommitment),
    }

    /// Wire: [u8 scheme] [inner PcsOpening bytes]
    enum PcsOpening has drop {
        Bls12381Fr(vss_bls12381_fr::PcsOpening),
    }

    /// Wire: [u8 scheme] [inner PcsBatchOpening bytes]
    enum PcsBatchOpening has drop {
        Bls12381Fr(vss_bls12381_fr::PcsBatchOpening),
    }

    // ── Public scheme constant ────────────────────────────────────────────────

    public fun scheme_bls12381_fr(): u8 { SCHEME_BLS12381FR }

    // ── Abstract deserialize functions ────────────────────────────────────────

    /// Parse a `PcsCommitment` from a BCS stream (reads the leading scheme byte).
    public fun deserialize_pcs_commitment(stream: &mut BCSStream): PcsCommitment {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_BLS12381FR) {
            PcsCommitment::Bls12381Fr(vss_bls12381_fr::deserialize_pcs_commitment(stream))
        } else {
            abort E_INVALID_CONTRIBUTION
        }
    }

    /// Parse a `PcsOpening` from a BCS stream (reads the leading scheme byte).
    public fun deserialize_pcs_opening(stream: &mut BCSStream): PcsOpening {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_BLS12381FR) {
            PcsOpening::Bls12381Fr(vss_bls12381_fr::deserialize_pcs_opening(stream))
        } else {
            abort E_INVALID_CONTRIBUTION
        }
    }

    /// Parse a `PcsBatchOpening` from a BCS stream (reads the leading scheme byte).
    public fun deserialize_pcs_batch_opening(stream: &mut BCSStream): PcsBatchOpening {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_BLS12381FR) {
            PcsBatchOpening::Bls12381Fr(vss_bls12381_fr::deserialize_pcs_batch_opening(stream))
        } else {
            abort E_INVALID_CONTRIBUTION
        }
    }

    // ── Abstract scheme getters and downcast accessors ────────────────────────

    public fun get_pcs_commitment_scheme(c: &PcsCommitment): u8 {
        match (c) {
            PcsCommitment::Bls12381Fr(_) => SCHEME_BLS12381FR,
        }
    }

    public fun pcs_commitment_as_bls12381_fr(c: PcsCommitment): vss_bls12381_fr::PcsCommitment {
        match (c) {
            PcsCommitment::Bls12381Fr(inner) => inner,
        }
    }

    public fun get_pcs_opening_scheme(o: &PcsOpening): u8 {
        match (o) {
            PcsOpening::Bls12381Fr(_) => SCHEME_BLS12381FR,
        }
    }

    public fun pcs_opening_as_bls12381_fr(o: PcsOpening): vss_bls12381_fr::PcsOpening {
        match (o) {
            PcsOpening::Bls12381Fr(inner) => inner,
        }
    }

    public fun get_pcs_batch_opening_scheme(o: &PcsBatchOpening): u8 {
        match (o) {
            PcsBatchOpening::Bls12381Fr(_) => SCHEME_BLS12381FR,
        }
    }

    public fun pcs_batch_opening_as_bls12381_fr(o: PcsBatchOpening): vss_bls12381_fr::PcsBatchOpening {
        match (o) {
            PcsBatchOpening::Bls12381Fr(inner) => inner,
        }
    }

    // ── View functions ───────────────────────────────────────────────────────

    /// Serialize a `Session` to BCS bytes compatible with ts-sdk `Session.fromBytes()`.
    /// Move's native `bcs::to_bytes` for `vector<u8>` fields would include a length prefix,
    /// but ts-sdk reads dc0/dc1 as u8 option tags. This function manually serializes with
    /// u8 option tags (0=None, 1=Some+payload) so the output can be deserialized by the SDK.
    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        let s = borrow_global<Session>(session_addr);
        let bytes = bcs::to_bytes(&s.dealer);
        bytes.append(bcs::to_bytes(&s.share_holders));
        bytes.append(bcs::to_bytes(&s.threshold));
        bytes.push_back(s.secret_scheme);
        bytes.push_back(s.state_code);
        bytes.append(bcs::to_bytes(&s.deal_time_micros));
        if (s.dealer_contribution_0.is_empty()) {
            bytes.push_back(0u8);
        } else {
            bytes.push_back(1u8);
            let n = s.dealer_contribution_0.length();
            let i = 0;
            while (i < n) {
                bytes.push_back(*s.dealer_contribution_0.borrow(i));
                i = i + 1;
            };
        };
        bytes.append(bcs::to_bytes(&s.share_holder_acks));
        if (s.dealer_contribution_1.is_empty()) {
            bytes.push_back(0u8);
        } else {
            bytes.push_back(1u8);
            let n = s.dealer_contribution_1.length();
            let i = 0;
            while (i < n) {
                bytes.push_back(*s.dealer_contribution_1.borrow(i));
                i = i + 1;
            };
        };
        bytes
    }

    // ── Entry functions ──────────────────────────────────────────────────────

    public fun new_session(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        secret_scheme: u8,
    ): address {
        assert!(worker_config::has_pke_enc_key(dealer), error::invalid_argument(E_INVALID_DEALER));
        share_holders.for_each(|share_holder| {
            assert!(worker_config::has_pke_enc_key(share_holder), error::invalid_argument(E_INVALID_RECIPIENT));
        });
        let num_share_holders = share_holders.length();
        assert!(threshold >= 2 && threshold * 2 > num_share_holders && threshold <= num_share_holders, error::invalid_argument(E_INVALID_THRESHOLD));
        assert!(secret_scheme == SECRET_SCHEME__BLS12381G1 || secret_scheme == SECRET_SCHEME__BLS12381G2, error::invalid_argument(E_UNSUPORTED_SECRET_SCHEME));
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();
        let session = Session {
            dealer,
            share_holders,
            threshold,
            secret_scheme,
            deal_time_micros: 0,
            state_code: STATE__DEALER_DEAL,
            dealer_contribution_0: vector[],
            share_holder_acks: range(0, num_share_holders).map(|_| false),
            dealer_contribution_1: vector[],
        };
        move_to(&object_signer, session);
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    public entry fun new_session_entry(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        secret_scheme: u8,
    ) {
        new_session(caller, dealer, share_holders, threshold, secret_scheme);
    }

    public entry fun on_dealer_contribution_0(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(session.state_code == STATE__DEALER_DEAL, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        if (session.secret_scheme == SECRET_SCHEME__BLS12381G1) {
            let _dc0 = vss_bls12381_fr::parse_dealer_contribution_0(copy payload_bytes);
        } else {
            abort error::invalid_argument(E_UNSUPORTED_SECRET_SCHEME)
        };
        session.dealer_contribution_0 = payload_bytes;
        session.state_code = STATE__RECIPIENT_ACK;
        session.deal_time_micros = timestamp::now_microseconds();
    }

    public entry fun on_share_holder_ack(
        recipient: &signer,
        session_addr: address,
    ) {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(session.state_code == STATE__RECIPIENT_ACK, error::invalid_state(E_NOT_IN_PROGRESS));
        let recipient_addr = address_of(recipient);
        let (found, idx) = session.share_holders.index_of(&recipient_addr);
        assert!(found, error::permission_denied(E_RECIPIENT_NOT_FOUND));
        session.share_holder_acks[idx] = true;
    }

    public entry fun on_dealer_open(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(session.state_code == STATE__RECIPIENT_ACK, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(timestamp::now_microseconds() - session.deal_time_micros > ACK_WINDOW_MICROS, error::invalid_state(E_TOO_EARLY_TO_OPEN));
        if (session.secret_scheme == SECRET_SCHEME__BLS12381G1) {
            let _dc1 = vss_bls12381_fr::parse_dealer_contribution_1(copy payload_bytes);
        } else {
            abort error::invalid_argument(E_UNSUPORTED_SECRET_SCHEME)
        };
        session.dealer_contribution_1 = payload_bytes;
        session.state_code = STATE__SUCCESS;
    }
}

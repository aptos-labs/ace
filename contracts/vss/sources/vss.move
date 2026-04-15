// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// VSS abstract layer — on-chain session management.
/// Mirrors ts-sdk/src/vss/index.ts.
///
/// Group-level types (Scalar, Element) and arithmetic live in ace::group.
module ace::vss {
    use std::bcs;
    use std::error;
    use std::signer::address_of;
    use std::vector::{range};
    use aptos_framework::object;
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use ace::group;
    use ace::worker_config;
    use ace::pke;
    use std::option::{Option, Self};
    use aptos_std::bcs_stream::{Self, BCSStream};

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID_CONTRIBUTION: u64 = 16;
    const E_ALREADY_CONTRIBUTED: u64 = 15;
    const E_ONLT_DEALER_CAN_DO_THIS: u64 = 18;
    const E_ESCROW_TOO_LARGE: u64 = 19;
    const E_NOT_IN_PROGRESS: u64 = 20;
    const E_INVALID_DEALER: u64 = 21;
    const E_INVALID_RECIPIENT: u64 = 22;
    const E_INVALID_THRESHOLD: u64 = 23;
    const E_RECIPIENT_NOT_FOUND: u64 = 25;
    const E_NOT_ENOUGH_ACKS: u64 = 26;
    const E_INVALID_MSM: u64 = 28;
    const E_INVALID_REVEALED_SHARE: u64 = 29;
    const E_NOT_ALL_RECIPIENTS_COVERED: u64 = 30;
    const E_NOT_COMPLETED: u64 = 32;

    // ── Protocol constants ───────────────────────────────────────────────────

    const ACK_WINDOW_MICROS: u64 = 5_000_000; // 5 seconds for localnet

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__SUCCESS: u8 = 2;
    const STATE__FAILED: u8 = 3;

    // ── On-chain session state ────────────────────────────────────────────────

    struct PcsCommitment has copy, drop, store {
        points: vector<group::Element>,
    }

    struct DealerContribution0 has copy, drop, store {
        pcs_commitment: PcsCommitment,
        private_share_messages: vector<pke::Ciphertext>,
        dealer_state: Option<pke::Ciphertext>,
    }

    struct DealerContribution1 has copy, drop, store {
        shares_to_reveal: vector<Option<group::Scalar>>,
    }

    struct Session has key {
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        public_base_element: group::Element,
        state_code: u8,
        deal_time_micros: u64,
        dealer_contribution_0: Option<DealerContribution0>,
        share_holder_acks: vector<bool>,
        dealer_contribution_1: Option<DealerContribution1>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    // ── View functions ───────────────────────────────────────────────────────

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        let s = borrow_global<Session>(session_addr);
        bcs::to_bytes(s)
    }

    // ── Entry functions ──────────────────────────────────────────────────────

    public fun new_session(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        public_base_element: group::Element,
    ): address {
        assert!(worker_config::has_pke_enc_key(dealer), error::invalid_argument(E_INVALID_DEALER));
        share_holders.for_each(|share_holder| {
            assert!(worker_config::has_pke_enc_key(share_holder), error::invalid_argument(E_INVALID_RECIPIENT));
        });
        let num_share_holders = share_holders.length();
        assert!(threshold >= 2 && threshold * 2 > num_share_holders && threshold <= num_share_holders, error::invalid_argument(E_INVALID_THRESHOLD));
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();
        let session = Session {
            dealer,
            share_holders,
            threshold,
            public_base_element,
            deal_time_micros: 0,
            state_code: STATE__DEALER_DEAL,
            dealer_contribution_0: option::none(),
            share_holder_acks: range(0, num_share_holders).map(|_| false),
            dealer_contribution_1: option::none(),
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
        base_point_bytes: vector<u8>,
    ) {
        let base_point = group::element_from_bytes(base_point_bytes);
        new_session(caller, dealer, share_holders, threshold, base_point);
    }

    public entry fun on_dealer_contribution_0(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(session.state_code == STATE__DEALER_DEAL, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        let dc0 = dealer_contribution_0_from_bytes(payload_bytes);
        session.dealer_contribution_0 = option::some(dc0);
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
        assert!(timestamp::now_microseconds() - session.deal_time_micros > ACK_WINDOW_MICROS, error::invalid_state(E_NOT_ENOUGH_ACKS));
        let dc1 = dealer_contribution_1_from_bytes(payload_bytes);

        // Should not proceed without enough acks.
        let num_acks = session.share_holder_acks.filter(|ack| *ack).length();
        assert!(num_acks >= session.threshold, error::invalid_state(E_NOT_ENOUGH_ACKS));

        // Every recipient should either acked or have their shares being revealed.
        let all_recipient_covered = range(0, session.share_holders.length()).all(|i| {
            let ack = session.share_holder_acks[*i];
            let revealed = dc1.shares_to_reveal[*i].is_some();
            ack == !revealed
        });
        assert!(all_recipient_covered, error::invalid_state(E_NOT_ALL_RECIPIENTS_COVERED));

        // Verify the revealed shares in dc1 match the commitment in dc0.
        let n = session.share_holders.length();
        let dc0 = session.dealer_contribution_0.borrow();
        let scheme = group::element_scheme(&session.public_base_element);
        range(0, n).for_each(|i| {
            if (dc1.shares_to_reveal[i].is_some()) {
                let x = group::scalar_from_u64(scheme, i + 1);
                let powers_of_x = vector[group::scalar_from_u64(scheme, 1)];
                let accumulator = group::scalar_from_u64(scheme, 1);
                range(0, session.threshold - 1).for_each(|_| {
                    accumulator = group::scalar_mul(&accumulator, &x);
                    powers_of_x.push_back(accumulator);
                });

                let revealed_share = dc1.shares_to_reveal[i].borrow();
                let lhs = group::scale_element(&session.public_base_element, revealed_share);
                let rhs = group::msm(dc0.pcs_commitment.points, powers_of_x);
                assert!(group::element_eq(&lhs, &rhs), error::invalid_state(E_INVALID_REVEALED_SHARE));
            }
        });

        // All checks passed.
        session.dealer_contribution_1 = option::some(dc1);
        session.state_code = STATE__SUCCESS;
    }

    public fun completed(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.state_code == STATE__SUCCESS
    }

    public fun result_pk(session_addr: address): group::Element acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.dealer_contribution_0.borrow().pcs_commitment.points[0]
    }

    public fun ack_vec(session_addr: address): vector<u8> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.share_holder_acks.map(|ack| if (ack) 1 else 0)
    }

    // ── Serde helpers ────────────────────────────────────────────────────────

    fun deserialize_pcs_commitment(stream: &mut BCSStream): PcsCommitment {
        let points = bcs_stream::deserialize_vector(stream, |s| group::deserialize_element(s));
        PcsCommitment { points }
    }

    fun dealer_contribution_0_from_bytes(bytes: vector<u8>): DealerContribution0 {
        let stream = bcs_stream::new(bytes);
        let pcs_commitment = deserialize_pcs_commitment(&mut stream);
        let private_share_messages = bcs_stream::deserialize_vector(&mut stream, |s| pke::deserialize_ciphertext(s));
        let dealer_state = bcs_stream::deserialize_option(&mut stream, |s| pke::deserialize_ciphertext(s));
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution0 { pcs_commitment, private_share_messages, dealer_state }
    }

    fun dealer_contribution_1_from_bytes(bytes: vector<u8>): DealerContribution1 {
        let stream = bcs_stream::new(bytes);
        let shares_to_reveal = bcs_stream::deserialize_vector(&mut stream, |s| {
            bcs_stream::deserialize_option(s, |s| group::deserialize_scalar(s))
        });
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution1 { shares_to_reveal }
    }

    // ── Test-only helpers ────────────────────────────────────────────────────

    #[test_only]
    public fun dc1_from_bytes_for_testing(bytes: vector<u8>): DealerContribution1 {
        dealer_contribution_1_from_bytes(bytes)
    }

    #[test_only]
    public fun dc1_len(dc1: &DealerContribution1): u64 {
        dc1.shares_to_reveal.length()
    }

    #[test_only]
    public fun dc1_is_none_at(dc1: &DealerContribution1, i: u64): bool {
        dc1.shares_to_reveal[i].is_none()
    }

    #[test_only]
    public fun dc1_is_some_at(dc1: &DealerContribution1, i: u64): bool {
        dc1.shares_to_reveal[i].is_some()
    }
}

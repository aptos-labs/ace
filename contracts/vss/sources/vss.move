// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// VSS sub-session object: one dealer slot within a DKG or DKR parent session.
module ace::vss {
    use std::error;
    use std::signer::address_of;
    use std::vector::{range};
    use aptos_framework::object;
    use aptos_framework::event;
    use ace::worker_config;
    use aptos_framework::timestamp;

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

    const ACK_WINDOW_MICROS: u64 = 20000000; // 20 seconds

    const SECRET_SCHEME__BLS12381G1: u8 = 0;
    const SECRET_SCHEME__BLS12381G2: u8 = 1;

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__SUCCESS: u8 = 2;
    const STATE__FAILED: u8 = 3;
    
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
        session.dealer_contribution_1 = payload_bytes;
        //TODO: verify dealer contribution 1
        session.state_code = STATE__SUCCESS;
    }
}

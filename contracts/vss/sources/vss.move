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
    use aptos_framework::chain_id;
    use ace::group;
    use ace::worker_config;
    use ace::pke;
    use std::option::{Option, Self};
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::fiat_shamir_transform;
    use ace::sigma_dlog_eq;

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
    const E_INVALID_SCALED_ELEMENT_PROOF: u64 = 33;
    const E_INVALID_COMMITMENT_FOR_RESHARING: u64 = 34;
    const E_TOO_EARLY_TO_OPEN: u64 = 35;
    
    // ── Protocol constants ───────────────────────────────────────────────────

    const ACK_WINDOW_MICROS: u64 = 10_000_000; // 5 seconds for localnet

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__SUCCESS: u8 = 2;
    const STATE__FAILED: u8 = 3;

    // ── On-chain session state ────────────────────────────────────────────────

    struct PcsCommitment has copy, drop, store {
        points: vector<group::Element>,
    }

    struct FiatShamirTag has copy, drop, store {
        chain_id: u8,
        module_addr: address,
        module_name: vector<u8>,
    }

    /// Sometimes the VSS is for resharing a secret, and the caller will want the dealer to prove knowledge of the secret.
    struct ResharingDealerChallenge has copy, drop, store {
        expected_scaled_element: group::Element,
        another_base_element: group::Element,
    }

    struct ResharingDealerResponse has copy, drop, store {
        another_scaled_element: group::Element,
        proof: sigma_dlog_eq::Proof,
    }

    struct DealerContribution0 has copy, drop, store {
        pcs_commitment: PcsCommitment,
        private_share_messages: vector<pke::Ciphertext>,
        dealer_state: Option<pke::Ciphertext>,
        resharing_response: Option<ResharingDealerResponse>,
    }

    struct DealerContribution1 has copy, drop, store {
        shares_to_reveal: vector<Option<group::Scalar>>,
    }

    struct Session has key {
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        public_base_element: group::Element,
        /// If present, the dealer must deal the corresponding secret scaler and provide a proof of knowledge of such secret.
        resharing_challenge: Option<ResharingDealerChallenge>,
        state_code: u8,
        deal_time_micros: u64,
        dealer_contribution_0: Option<DealerContribution0>,
        share_holder_acks: vector<bool>,
        dealer_contribution_1: Option<DealerContribution1>,
        /// Per-holder share PKs, computed at SUCCESS: share_pks[i] = g^{f(i+1)} where f is the dealer's polynomial.
        /// Empty until state_code == STATE__SUCCESS.
        share_pks: vector<group::Element>,
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

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        public_base_element: group::Element,
        expected_scaled_element: Option<group::Element>,
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
        let resharing_challenge = if (expected_scaled_element.is_some()) {
            let challenge = ResharingDealerChallenge {
                expected_scaled_element: *expected_scaled_element.borrow(),
                another_base_element: group::element_from_hash(
                    group::element_scheme(&public_base_element),
                    &bcs::to_bytes(expected_scaled_element.borrow()),
                ),
            };
            option::some(challenge)
        } else {
            option::none()
        };
        let session = Session {
            dealer,
            share_holders,
            threshold,
            public_base_element,
            resharing_challenge,
            deal_time_micros: 0,
            state_code: STATE__DEALER_DEAL,
            dealer_contribution_0: option::none(),
            share_holder_acks: range(0, num_share_holders).map(|_| false),
            dealer_contribution_1: option::none(),
            share_pks: vector[],
        };
        move_to(&object_signer, session);
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    #[randomness]
    entry fun new_session_entry(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        public_base_element: vector<u8>,
        secretly_scaled_element: vector<u8>,
    ) {
        let public_base_element = group::element_from_bytes(public_base_element);
        let secretly_scaled_element = if (secretly_scaled_element.length() > 0) {
            option::some(group::element_from_bytes(secretly_scaled_element))
        } else {
            option::none()
        };
        new_session(caller, dealer, share_holders, threshold, public_base_element, secretly_scaled_element);
    }

    public entry fun on_dealer_contribution_0(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(session.state_code == STATE__DEALER_DEAL, error::invalid_state(E_NOT_IN_PROGRESS));
        let dc0 = dealer_contribution_0_from_bytes(payload_bytes);
        if (session.resharing_challenge.is_some()) {
            assert!(dc0.resharing_response.is_some(), error::invalid_argument(E_INVALID_SCALED_ELEMENT_PROOF));
            let resharing_challenge = session.resharing_challenge.borrow();
            let resharing_response = dc0.resharing_response.borrow();
            assert!(group::element_eq(&resharing_challenge.expected_scaled_element, &dc0.pcs_commitment.points[0]), error::invalid_argument(E_INVALID_COMMITMENT_FOR_RESHARING));
            let trx = fiat_shamir_transform::new_transcript();
            let domain_tag = FiatShamirTag {
                chain_id: chain_id::get(),
                module_addr: @ace,
                module_name: b"vss",
            };
            fiat_shamir_transform::append_raw_bytes(&mut trx, bcs::to_bytes(&domain_tag));
            let valid = sigma_dlog_eq::verify(
                &mut trx,
                &session.public_base_element,
                &resharing_challenge.expected_scaled_element,
                &resharing_challenge.another_base_element,
                &resharing_response.another_scaled_element,
                &resharing_response.proof,
            );
            assert!(valid, error::invalid_argument(E_INVALID_SCALED_ELEMENT_PROOF));
        };
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
        assert!(timestamp::now_microseconds() - session.deal_time_micros > ACK_WINDOW_MICROS, error::invalid_state(E_TOO_EARLY_TO_OPEN));
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
        assert!(all_recipient_covered, error::invalid_argument(E_NOT_ALL_RECIPIENTS_COVERED));

        // Single pass: verify revealed shares against commitment AND compute all share_pks.
        // share_pks[i] = MSM(commitment, [1, x, x², …]) at x = i+1; reused as the lhs check for revealed shares.
        let n = session.share_holders.length();
        let scheme = group::element_scheme(&session.public_base_element);
        let commitment_points = session.dealer_contribution_0.borrow().pcs_commitment.points;
        let t = session.threshold;
        let i = 0u64;
        while (i < n) {
            let x = group::scalar_from_u64(scheme, i + 1);
            let share_pk = group::msm(commitment_points, build_powers_of_x(scheme, &x, t));
            if (dc1.shares_to_reveal[i].is_some()) {
                let revealed_share = dc1.shares_to_reveal[i].borrow();
                let lhs = group::scale_element(&session.public_base_element, revealed_share);
                assert!(group::element_eq(&lhs, &share_pk), error::invalid_argument(E_INVALID_REVEALED_SHARE));
            };
            session.share_pks.push_back(share_pk);
            i += 1;
        };

        // All checks passed.
        session.dealer_contribution_1 = option::some(dc1);
        session.state_code = STATE__SUCCESS;
    }

    fun build_powers_of_x(scheme: u8, x: &group::Scalar, t: u64): vector<group::Scalar> {
        let powers = vector[group::scalar_from_u64(scheme, 1)];
        let acc = group::scalar_from_u64(scheme, 1);
        range(0, t - 1).for_each(|_| {
            acc = group::scalar_mul(&acc, x);
            powers.push_back(acc);
        });
        powers
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

    /// Returns the Feldman commitment points for a completed VSS session.
    public fun pcs_commitment_points(session_addr: address): vector<group::Element> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.dealer_contribution_0.borrow().pcs_commitment.points
    }

    /// Returns the per-holder share PKs for a completed VSS session.
    /// share_pks[i] = g^{f(i+1)} where f is the dealer's polynomial.
    public fun share_pks(session_addr: address): vector<group::Element> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.share_pks
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

    fun deserialize_resharing_dealer_response(stream: &mut BCSStream): ResharingDealerResponse {
        let another_scaled_element = group::deserialize_element(stream);
        let proof = sigma_dlog_eq::deserialize_proof(stream);
        ResharingDealerResponse { another_scaled_element, proof }
    }

    fun dealer_contribution_0_from_bytes(bytes: vector<u8>): DealerContribution0 {
        let stream = bcs_stream::new(bytes);
        let pcs_commitment = deserialize_pcs_commitment(&mut stream);
        let private_share_messages = bcs_stream::deserialize_vector(&mut stream, |s| pke::deserialize_ciphertext(s));
        let dealer_state = bcs_stream::deserialize_option(&mut stream, |s| pke::deserialize_ciphertext(s));
        let resharing_response = bcs_stream::deserialize_option(&mut stream, |s| deserialize_resharing_dealer_response(s));
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution0 { pcs_commitment, private_share_messages, dealer_state, resharing_response }
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

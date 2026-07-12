// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// VSS abstract layer -- on-chain session management.
/// Mirrors ts-sdk/src/vss/index.ts.
///
/// Group-level types (Scalar, Element) and arithmetic live in ace::group.
module ace::vss {
    use std::bcs;
    use std::error;
    use std::vector::range;
    use aptos_framework::chain_id;
    use aptos_framework::event;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use aptos_std::bcs_stream;
    use std::option::{Option, Self};
    use ace::fiat_shamir_transform;
    use ace::group;
    use ace::pedersen_polynomial_commitment;
    use ace::sigma_dlog_linear;
    use ace::worker_config;

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID_CONTRIBUTION: u64 = 16;
    const E_ALREADY_CONTRIBUTED: u64 = 15;
    const E_ONLT_DEALER_CAN_DO_THIS: u64 = 18;
    const E_NOT_IN_PROGRESS: u64 = 20;
    const E_INVALID_DEALER: u64 = 21;
    const E_INVALID_RECIPIENT: u64 = 22;
    const E_INVALID_THRESHOLD: u64 = 23;
    const E_RECIPIENT_NOT_FOUND: u64 = 25;
    const E_NOT_ALL_RECIPIENTS_COVERED: u64 = 30;
    const E_NOT_COMPLETED: u64 = 32;
    const E_INVALID_CONSISTENCY_PROOF: u64 = 33;
    const E_TOO_EARLY_TO_OPEN: u64 = 35;
    const E_GROUP_SCHEME_MISMATCH: u64 = 36;
    const E_INVALID_PUBLIC_KEY_PROOF: u64 = 37;

    // ── Protocol constants ───────────────────────────────────────────────────

    const ACK_WINDOW_MICROS: u64 = 10_000_000; // 10 seconds for localnet

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__VERIFY_DEALER_OPENING: u8 = 2;
    const STATE__SUCCESS: u8 = 3;
    const STATE__FAILED: u8 = 4;

    // ── On-chain session state ────────────────────────────────────────────────

    /// Previous Pedersen commitment statement for a reshare.
    ///
    /// A reshare VSS must prove its new position-0 commitment commits to the
    /// same secret scalar as this old commitment point:
    ///   old_c = s * old_g + old_r * old_h
    ///   new_c = s * new_g + new_r * new_h
    struct PreviousCommitment has copy, drop, store {
        old_g: group::Element,
        old_h: group::Element,
        old_c: group::Element,
    }

    struct DealerContribution0 has copy, drop, store {
        pcs_commitment: pedersen_polynomial_commitment::Commitment,
        consistency_proof: Option<sigma_dlog_linear::Proof>,
    }

    /// All vectors are indexed on the ACE PCS domain {0, 1, ..., n}.
    ///
    /// shares_to_reveal[0] is always None. For i >= 1, it is Some(opening) iff
    /// holder i did not ACK.
    struct DealerContribution1 has copy, drop, store {
        shares_to_reveal: vector<Option<pedersen_polynomial_commitment::Opening>>,
        /// public_keys[i] = p(i) * G, where G is pcs_context.generator_g.
        public_keys: vector<group::Element>,
        /// A proof is present exactly when the corresponding opening remains private.
        public_key_proofs: vector<Option<sigma_dlog_linear::Proof>>,
    }

    struct Session has key {
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        scheme: u8,
        previous_commitment: Option<PreviousCommitment>,
        pcs_context: pedersen_polynomial_commitment::PublicParams,
        state_code: u8,
        deal_time_micros: u64,
        dealer_contribution_0: Option<DealerContribution0>,
        dealer_commitment_check: pedersen_polynomial_commitment::DegreeCheckState,
        share_holder_acks: vector<bool>,
        dealer_contribution_1: Option<DealerContribution1>,
        next_public_key_to_verify: u64,
        /// Verified public keys over the ACE domain {0, 1, ..., n}.
        public_keys: vector<group::Element>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    // ── View functions ───────────────────────────────────────────────────────

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> {
        bcs::to_bytes(&Session[session_addr])
    }

    // ── Entry functions ──────────────────────────────────────────────────────

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        caller: &signer,
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        scheme: u8,
        pcs_context: Option<pedersen_polynomial_commitment::PublicParams>,
        previous_commitment: Option<PreviousCommitment>,
    ): address {
        assert!(worker_config::has_pke_enc_key(dealer), error::invalid_argument(E_INVALID_DEALER));
        share_holders.for_each(|share_holder| {
            assert!(worker_config::has_pke_enc_key(share_holder), error::invalid_argument(E_INVALID_RECIPIENT));
        });
        let num_share_holders = share_holders.length();
        assert!(
            threshold >= 2 && threshold * 2 > num_share_holders && threshold <= num_share_holders,
            error::invalid_argument(E_INVALID_THRESHOLD),
        );

        let pcs_context = if (pcs_context.is_some()) {
            let context = *pcs_context.borrow();
            assert!(pcs_context_scheme(&context) == scheme, error::invalid_argument(E_GROUP_SCHEME_MISMATCH));
            context
        } else {
            pedersen_polynomial_commitment::new_context(scheme)
        };
        if (previous_commitment.is_some()) assert!(
            previous_commitment_has_scheme(previous_commitment.borrow(), scheme),
            error::invalid_argument(E_GROUP_SCHEME_MISMATCH),
        );

        let caller_addr = caller.address_of();
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();

        let session = Session {
            dealer,
            share_holders,
            threshold,
            scheme,
            previous_commitment,
            pcs_context,
            deal_time_micros: 0,
            state_code: STATE__DEALER_DEAL,
            dealer_contribution_0: option::none(),
            dealer_commitment_check: pedersen_polynomial_commitment::empty_degree_check_state(&pcs_context),
            share_holder_acks: range(0, num_share_holders).map(|_| false),
            dealer_contribution_1: option::none(),
            next_public_key_to_verify: 0,
            public_keys: vector[],
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
        scheme: u8,
        pcs_context: vector<u8>,
        previous_commitment: vector<u8>,
    ) {
        let pcs_context = if (pcs_context.length() > 0) {
            option::some(pedersen_polynomial_commitment::public_params_from_bytes(pcs_context))
        } else {
            option::none()
        };
        let previous_commitment = if (previous_commitment.length() > 0) {
            option::some(previous_commitment_from_bytes(previous_commitment))
        } else {
            option::none()
        };
        new_session(caller, dealer, share_holders, threshold, scheme, pcs_context, previous_commitment);
    }

    #[randomness]
    entry fun on_dealer_contribution_0(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = &mut Session[session_addr];
        assert!(dealer.address_of() == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(session.state_code == STATE__DEALER_DEAL, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(session.dealer_contribution_0.is_none(), error::invalid_state(E_ALREADY_CONTRIBUTED));

        let dc0 = dealer_contribution_0_from_bytes(payload_bytes);
        let n = session.share_holders.length();
        assert!(
            pedersen_polynomial_commitment::commitment_len(&dc0.pcs_commitment) == n,
            error::invalid_argument(E_INVALID_CONTRIBUTION),
        );

        if (session.previous_commitment.is_some()) {
            assert!(dc0.consistency_proof.is_some(), error::invalid_argument(E_INVALID_CONSISTENCY_PROOF));
            assert!(
                verify_same_secret_proof(session_addr, session, &dc0),
                error::invalid_argument(E_INVALID_CONSISTENCY_PROOF),
            );
        } else {
            assert!(dc0.consistency_proof.is_none(), error::invalid_argument(E_INVALID_CONSISTENCY_PROOF));
        };

        let dealer_commitment_check = pedersen_polynomial_commitment::degree_check_start(
            &session.pcs_context,
            &dc0.pcs_commitment,
            session.threshold - 1,
        );

        session.dealer_contribution_0 = option::some(dc0);
        session.dealer_commitment_check = dealer_commitment_check;
    }

    public entry fun on_share_holder_ack(
        recipient: &signer,
        session_addr: address,
    ) {
        let session = &mut Session[session_addr];
        assert!(session.state_code == STATE__RECIPIENT_ACK, error::invalid_state(E_NOT_IN_PROGRESS));
        let recipient_addr = recipient.address_of();
        let (found, idx) = session.share_holders.index_of(&recipient_addr);
        assert!(found, error::permission_denied(E_RECIPIENT_NOT_FOUND));
        assert!(!session.share_holder_acks[idx], error::invalid_state(E_ALREADY_CONTRIBUTED));
        session.share_holder_acks[idx] = true;
    }

    entry fun on_dealer_open(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = &mut Session[session_addr];
        assert!(session.state_code == STATE__RECIPIENT_ACK, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(dealer.address_of() == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(timestamp::now_microseconds() - session.deal_time_micros > ACK_WINDOW_MICROS, error::invalid_state(E_TOO_EARLY_TO_OPEN));

        let dc1 = dealer_contribution_1_from_bytes(payload_bytes);
        let n = session.share_holders.length();
        let expected_len = n + 1;
        assert!(dc1.shares_to_reveal.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_keys.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_key_proofs.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.shares_to_reveal[0].is_none(), error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_key_proofs[0].is_some(), error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(elements_have_scheme(&dc1.public_keys, session.scheme), error::invalid_argument(E_GROUP_SCHEME_MISMATCH));

        let all_recipient_covered = range(1, expected_len).all(|i| {
            let ack = session.share_holder_acks[*i - 1];
            let revealed = dc1.shares_to_reveal[*i].is_some();
            let proved = dc1.public_key_proofs[*i].is_some();
            if (ack) {
                !revealed && proved
            } else {
                revealed && !proved
            }
        });
        assert!(all_recipient_covered, error::invalid_argument(E_NOT_ALL_RECIPIENTS_COVERED));

        session.dealer_contribution_1 = option::some(dc1);
        session.next_public_key_to_verify = 0;
        session.public_keys = vector[];
        session.state_code = STATE__VERIFY_DEALER_OPENING;
    }

    entry fun touch(session_addr: address) {
        let session = &mut Session[session_addr];
        if (session.state_code == STATE__DEALER_DEAL) {
            if (session.dealer_contribution_0.is_some()) {
                touch_dealer_commitment(session);
            };
            return;
        };

        if (session.state_code != STATE__VERIFY_DEALER_OPENING) return;

        let expected_len = session.share_holders.length() + 1;
        let eval_position = session.next_public_key_to_verify;
        if (eval_position >= expected_len) {
            session.state_code = STATE__SUCCESS;
            return;
        };

        verify_public_key_at(session_addr, session, eval_position);
        session.public_keys.push_back(session.dealer_contribution_1.borrow().public_keys[eval_position]);
        session.next_public_key_to_verify = eval_position + 1;
        if (session.next_public_key_to_verify == expected_len) {
            session.state_code = STATE__SUCCESS;
        };
    }

    fun touch_dealer_commitment(session: &mut Session) {
        let dc0 = session.dealer_contribution_0.borrow();
        if (pedersen_polynomial_commitment::degree_check_touch(
            &session.pcs_context,
            &dc0.pcs_commitment,
            &mut session.dealer_commitment_check,
        )) {
            finish_dealer_commitment_check(session);
        };
    }

    fun finish_dealer_commitment_check(session: &mut Session) {
        let dc0 = session.dealer_contribution_0.borrow();
        if (pedersen_polynomial_commitment::degree_check_accepts(&session.pcs_context, &dc0.pcs_commitment, &session.dealer_commitment_check)) {
            session.state_code = STATE__RECIPIENT_ACK;
            session.deal_time_micros = timestamp::now_microseconds();
        } else {
            session.state_code = STATE__FAILED;
        };
    }

    public fun completed(session_addr: address): bool {
        let session = &Session[session_addr];
        session.state_code == STATE__SUCCESS
    }

    /// Returns the Pedersen PCS commitment points for a completed VSS session.
    public fun pcs_commitment_points(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        pedersen_polynomial_commitment::commitment_points(&session.dealer_contribution_0.borrow().pcs_commitment)
    }

    /// Returns p(0) * G for a completed VSS session.
    public fun result_pk(session_addr: address): group::Element {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.public_keys[0]
    }

    public fun public_keys(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.public_keys
    }

    /// Returns p(i) * G for holder positions i in 1..=n.
    public fun share_pks(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        range(1, session.public_keys.length()).map(|i| session.public_keys[i])
    }

    public fun previous_commitment_from_parts(
        old_g: group::Element,
        old_h: group::Element,
        old_c: group::Element,
    ): PreviousCommitment {
        let previous = PreviousCommitment { old_g, old_h, old_c };
        assert!(
            previous_commitment_has_scheme(&previous, group::element_scheme(&old_g)),
            error::invalid_argument(E_GROUP_SCHEME_MISMATCH),
        );
        previous
    }

    public fun ack_vec(session_addr: address): vector<u8> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.share_holder_acks.map(|ack| if (ack) 1 else 0)
    }

    fun verify_same_secret_proof(session_addr: address, session: &Session, dc0: &DealerContribution0): bool {
        let previous = session.previous_commitment.borrow();
        let new_g = pedersen_polynomial_commitment::generator_g(&session.pcs_context);
        let new_h = pedersen_polynomial_commitment::generator_h(&session.pcs_context);
        let old_c = previous.old_c;
        let new_c = pedersen_polynomial_commitment::commitment_point(&dc0.pcs_commitment, 0);
        let identity = group::identity(session.scheme);

        let b_vals = vector[
            previous.old_g, previous.old_h, identity,
            new_g, identity, new_h,
        ];
        let p_vals = vector[old_c, new_c];
        let transcript = vss_transcript(session_addr, b"vss::dc0-same-secret", 0);
        sigma_dlog_linear::verify(&mut transcript, &b_vals, &p_vals, dc0.consistency_proof.borrow())
    }

    fun verify_public_key_at(session_addr: address, session: &Session, eval_position: u64) {
        let dc0 = session.dealer_contribution_0.borrow();
        let dc1 = session.dealer_contribution_1.borrow();
        let public_key = dc1.public_keys[eval_position];

        if (dc1.shares_to_reveal[eval_position].is_some()) {
            let opening = dc1.shares_to_reveal[eval_position].borrow();
            verify_revealed_share(session, eval_position, opening);
            let expected_public_key = group::scale_element(
                &pedersen_polynomial_commitment::generator_g(&session.pcs_context),
                &pedersen_polynomial_commitment::opening_eval_value_p(opening),
            );
            assert!(
                group::element_eq(&public_key, &expected_public_key),
                error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF),
            );
            return;
        };

        assert!(dc1.public_key_proofs[eval_position].is_some(), error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF));
        let generator_g = pedersen_polynomial_commitment::generator_g(&session.pcs_context);
        let generator_h = pedersen_polynomial_commitment::generator_h(&session.pcs_context);
        let identity = group::identity(session.scheme);
        let b_vals = vector[
            generator_g, identity,
            generator_g, generator_h,
        ];
        let p_vals = vector[
            public_key,
            pedersen_polynomial_commitment::commitment_point(&dc0.pcs_commitment, eval_position),
        ];
        let transcript = vss_transcript(session_addr, b"vss::dc1-public-key", eval_position);
        assert!(
            sigma_dlog_linear::verify(
                &mut transcript,
                &b_vals,
                &p_vals,
                dc1.public_key_proofs[eval_position].borrow(),
            ),
            error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF),
        );
    }

    fun vss_transcript(
        session_addr: address,
        purpose: vector<u8>,
        eval_position: u64,
    ): fiat_shamir_transform::Transcript {
        let transcript = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut transcript, bcs::to_bytes(&chain_id::get()));
        fiat_shamir_transform::append_raw_bytes(&mut transcript, bcs::to_bytes(&@ace));
        fiat_shamir_transform::append_raw_bytes(&mut transcript, b"vss");
        fiat_shamir_transform::append_raw_bytes(&mut transcript, purpose);
        fiat_shamir_transform::append_raw_bytes(&mut transcript, bcs::to_bytes(&session_addr));
        fiat_shamir_transform::append_raw_bytes(&mut transcript, bcs::to_bytes(&eval_position));
        transcript
    }

    fun previous_commitment_has_scheme(previous: &PreviousCommitment, scheme: u8): bool {
        group::element_scheme(&previous.old_g) == scheme
            && group::element_scheme(&previous.old_h) == scheme
            && group::element_scheme(&previous.old_c) == scheme
    }

    fun elements_have_scheme(elements: &vector<group::Element>, scheme: u8): bool {
        elements.length() > 0 && elements.map_ref(|e| group::element_scheme(e)).all(|s| *s == scheme)
    }

    fun pcs_context_scheme(context: &pedersen_polynomial_commitment::PublicParams): u8 {
        let generator_g = pedersen_polynomial_commitment::generator_g(context);
        let generator_h = pedersen_polynomial_commitment::generator_h(context);
        let scheme = group::element_scheme(&generator_g);
        assert!(group::element_scheme(&generator_h) == scheme, error::invalid_argument(E_GROUP_SCHEME_MISMATCH));
        scheme
    }

    fun verify_revealed_share(
        session: &Session,
        eval_position: u64,
        opening: &pedersen_polynomial_commitment::Opening,
    ) {
        let dc0 = session.dealer_contribution_0.borrow();
        assert!(
            pedersen_polynomial_commitment::opening_eval_position(opening) == eval_position,
            error::invalid_argument(E_INVALID_CONTRIBUTION),
        );
        assert!(
            pedersen_polynomial_commitment::verify(&session.pcs_context, &dc0.pcs_commitment, opening),
            error::invalid_argument(E_INVALID_CONTRIBUTION),
        );
    }

    // ── Serde helpers ────────────────────────────────────────────────────────

    fun dealer_contribution_0_from_bytes(bytes: vector<u8>): DealerContribution0 {
        let stream = bcs_stream::new(bytes);
        let pcs_commitment = pedersen_polynomial_commitment::deserialize_commitment(&mut stream);
        let consistency_proof = bcs_stream::deserialize_option(&mut stream, |s| sigma_dlog_linear::deserialize_proof(s));
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution0 { pcs_commitment, consistency_proof }
    }

    fun dealer_contribution_1_from_bytes(bytes: vector<u8>): DealerContribution1 {
        let stream = bcs_stream::new(bytes);
        let shares_to_reveal = bcs_stream::deserialize_vector(&mut stream, |s| {
            bcs_stream::deserialize_option(s, |s| pedersen_polynomial_commitment::deserialize_opening(s))
        });
        let public_keys = bcs_stream::deserialize_vector(&mut stream, |s| group::deserialize_element(s));
        let public_key_proofs = bcs_stream::deserialize_vector(&mut stream, |s| {
            bcs_stream::deserialize_option(s, |s| sigma_dlog_linear::deserialize_proof(s))
        });
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution1 { shares_to_reveal, public_keys, public_key_proofs }
    }

    fun previous_commitment_from_bytes(bytes: vector<u8>): PreviousCommitment {
        let stream = bcs_stream::new(bytes);
        let old_g = group::deserialize_element(&mut stream);
        let old_h = group::deserialize_element(&mut stream);
        let old_c = group::deserialize_element(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        PreviousCommitment { old_g, old_h, old_c }
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

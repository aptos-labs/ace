// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// VSS abstract layer -- on-chain session management.
/// Mirrors ts-sdk/src/vss/index.ts.
///
/// Group-level types (Scalar, Element) and arithmetic live in ace::group.
module ace::vss {
    use std::bcs;
    use std::error;
    use std::signer::address_of;
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
    use ace::pke;
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
    const E_NOT_ENOUGH_ACKS: u64 = 26;
    const E_INVALID_REVEALED_SHARE: u64 = 29;
    const E_NOT_ALL_RECIPIENTS_COVERED: u64 = 30;
    const E_NOT_COMPLETED: u64 = 32;
    const E_INVALID_PUBLIC_KEY_PROOF: u64 = 33;
    const E_TOO_EARLY_TO_OPEN: u64 = 35;
    const E_PUBLIC_KEY_SCHEME_MISMATCH: u64 = 36;
    const E_NOT_ADMIN: u64 = 37;

    // ── Protocol constants ───────────────────────────────────────────────────

    const ACK_WINDOW_MICROS: u64 = 10_000_000; // 10 seconds for localnet

    const STATE__DEALER_DEAL: u8 = 0;
    const STATE__RECIPIENT_ACK: u8 = 1;
    const STATE__VERIFY_DEALER_OPENING: u8 = 2;
    const STATE__SUCCESS: u8 = 3;
    const STATE__FAILED: u8 = 4;

    // ── On-chain session state ────────────────────────────────────────────────

    struct DealerContribution0 has copy, drop, store {
        pcs_commitment: pedersen_polynomial_commitment::Commitment,
        private_share_messages: vector<pke::Ciphertext>,
        dealer_state: Option<pke::Ciphertext>,
        /// Proof that V_0 opens to the previously committed public key in a reshare.
        consistency_proof: Option<sigma_dlog_linear::Proof>,
    }

    /// All vectors are indexed on the ACE PCS domain {0, 1, ..., n}.
    ///
    /// shares_to_reveal[0] is always None. For i >= 1, it is Some(opening) iff
    /// holder i did not ACK.
    ///
    /// public_keys[i] = s_i * public_base_element.
    ///
    /// public_key_proofs[i] is Some iff s_i and r_i are not publicly opened.
    struct DealerContribution1 has copy, drop, store {
        shares_to_reveal: vector<Option<pedersen_polynomial_commitment::Opening>>,
        public_keys: vector<group::Element>,
        public_key_proofs: vector<Option<sigma_dlog_linear::Proof>>,
    }

    struct Session has key {
        dealer: address,
        share_holders: vector<address>,
        threshold: u64,
        /// The base element B. The session output is s_0 * B.
        public_base_element: group::Element,
        /// If present, this VSS is resharing a previously committed secret s_0,
        /// and this is the expected s_0 * B.
        previous_public_key: Option<group::Element>,
        pcs_context: pedersen_polynomial_commitment::PublicParams,
        state_code: u8,
        deal_time_micros: u64,
        dealer_contribution_0: Option<DealerContribution0>,
        dealer_commitment_check: pedersen_polynomial_commitment::DegreeCheckState,
        share_holder_acks: vector<bool>,
        dealer_contribution_1: Option<DealerContribution1>,
        /// Next position in {0, 1, ..., n} for touch() to verify from DC1.
        next_public_key_to_verify: u64,
        /// Verified public keys over {0, 1, ..., n}. Empty until DC1 validation
        /// starts; touch() appends one verified entry at a time.
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
        public_base_element: group::Element,
        previous_public_key: Option<group::Element>,
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

        let scheme = group::element_scheme(&public_base_element);
        if (previous_public_key.is_some()) {
            assert!(
                group::element_scheme(previous_public_key.borrow()) == scheme,
                error::invalid_argument(E_PUBLIC_KEY_SCHEME_MISMATCH),
            );
        };

        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();
        let pcs_context = pedersen_polynomial_commitment::new_context(scheme);

        let session = Session {
            dealer,
            share_holders,
            threshold,
            public_base_element,
            previous_public_key,
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

        // Snapshot feature configs.
        let feature_configs = feature_configs_or_empty(@ace);
        move_to(&object_signer, feature_configs);

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
        previous_public_key: vector<u8>,
    ) {
        let public_base_element = group::element_from_bytes(public_base_element);
        let previous_public_key = if (previous_public_key.length() > 0) {
            option::some(group::element_from_bytes(previous_public_key))
        } else {
            option::none()
        };
        new_session(caller, dealer, share_holders, threshold, public_base_element, previous_public_key);
    }

    #[randomness]
    entry fun on_dealer_contribution_0(
        dealer: &signer,
        session_addr: address,
        payload_bytes: vector<u8>,
    ) {
        let session = &mut Session[session_addr];
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(session.state_code == STATE__DEALER_DEAL, error::invalid_state(E_NOT_IN_PROGRESS));
        assert!(session.dealer_contribution_0.is_none(), error::invalid_state(E_ALREADY_CONTRIBUTED));

        let dc0 = dealer_contribution_0_from_bytes(payload_bytes);
        let n = session.share_holders.length();
        assert!(
            pedersen_polynomial_commitment::commitment_len(&dc0.pcs_commitment) == n,
            error::invalid_argument(E_INVALID_CONTRIBUTION),
        );
        assert!(dc0.private_share_messages.length() == n, error::invalid_argument(E_INVALID_CONTRIBUTION));

        if (session.previous_public_key.is_some()) {
            assert!(dc0.consistency_proof.is_some(), error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF));
            assert!(
                verify_public_key_proof(
                    session_addr,
                    b"vss::dc0-consistency",
                    &session.pcs_context,
                    &dc0.pcs_commitment,
                    &session.public_base_element,
                    0,
                    *session.previous_public_key.borrow(),
                    dc0.consistency_proof.borrow(),
                ),
                error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF),
            );
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
        let recipient_addr = address_of(recipient);
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
        assert!(address_of(dealer) == session.dealer, error::permission_denied(E_ONLT_DEALER_CAN_DO_THIS));
        assert!(timestamp::now_microseconds() - session.deal_time_micros > ACK_WINDOW_MICROS, error::invalid_state(E_TOO_EARLY_TO_OPEN));

        let dc1 = dealer_contribution_1_from_bytes(payload_bytes);
        let n = session.share_holders.length();
        let expected_len = n + 1;
        assert!(dc1.shares_to_reveal.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_keys.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_key_proofs.length() == expected_len, error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.shares_to_reveal[0].is_none(), error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(dc1.public_key_proofs[0].is_some(), error::invalid_argument(E_INVALID_CONTRIBUTION));
        assert!(elements_have_scheme(&dc1.public_keys, group::element_scheme(&session.public_base_element)), error::invalid_argument(E_PUBLIC_KEY_SCHEME_MISMATCH));

        let num_acks = session.share_holder_acks.filter(|ack| *ack).length();
        assert!(num_acks >= session.threshold, error::invalid_state(E_NOT_ENOUGH_ACKS));

        if (session.previous_public_key.is_some()) {
            assert!(
                group::element_eq(&dc1.public_keys[0], session.previous_public_key.borrow()),
                error::invalid_argument(E_INVALID_CONTRIBUTION),
            );
        };

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
        let public_key = session.dealer_contribution_1.borrow().public_keys[eval_position];
        session.public_keys.push_back(public_key);
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

    public fun result_pk(session_addr: address): group::Element {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.public_keys[0]
    }

    /// Returns the Pedersen PCS commitment points for a completed VSS session.
    public fun pcs_commitment_points(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        pedersen_polynomial_commitment::commitment_points(&session.dealer_contribution_0.borrow().pcs_commitment)
    }

    /// Returns the per-holder share public keys for a completed VSS session.
    public fun share_pks(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        range(1, session.public_keys.length()).map(|i| session.public_keys[i])
    }

    public fun ack_vec(session_addr: address): vector<u8> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__SUCCESS, error::invalid_state(E_NOT_COMPLETED));
        session.share_holder_acks.map(|ack| if (ack) 1 else 0)
    }

    fun verify_public_key_at(session_addr: address, session: &Session, eval_position: u64) {
        let dc0 = session.dealer_contribution_0.borrow();
        let dc1 = session.dealer_contribution_1.borrow();
        let public_key = dc1.public_keys[eval_position];

        if (eval_position == 0) {
            assert!(dc1.shares_to_reveal[0].is_none(), error::invalid_argument(E_INVALID_CONTRIBUTION));
            assert!(dc1.public_key_proofs[0].is_some(), error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF));
            assert!(
                verify_public_key_proof(
                    session_addr,
                    b"vss::dc1-public-key",
                    &session.pcs_context,
                    &dc0.pcs_commitment,
                    &session.public_base_element,
                    0,
                    public_key,
                    dc1.public_key_proofs[0].borrow(),
                ),
                error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF),
            );
            return;
        };

        if (session.share_holder_acks[eval_position - 1]) {
            assert!(dc1.shares_to_reveal[eval_position].is_none(), error::invalid_argument(E_INVALID_CONTRIBUTION));
            assert!(dc1.public_key_proofs[eval_position].is_some(), error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF));
            assert!(
                verify_public_key_proof(
                    session_addr,
                    b"vss::dc1-public-key",
                    &session.pcs_context,
                    &dc0.pcs_commitment,
                    &session.public_base_element,
                    eval_position,
                    public_key,
                    dc1.public_key_proofs[eval_position].borrow(),
                ),
                error::invalid_argument(E_INVALID_PUBLIC_KEY_PROOF),
            );
        } else {
            assert!(dc1.shares_to_reveal[eval_position].is_some(), error::invalid_argument(E_INVALID_CONTRIBUTION));
            let opening = dc1.shares_to_reveal[eval_position].borrow();
            assert!(
                pedersen_polynomial_commitment::opening_eval_position(opening) == eval_position,
                error::invalid_argument(E_INVALID_CONTRIBUTION),
            );
            assert!(
                pedersen_polynomial_commitment::verify(&session.pcs_context, &dc0.pcs_commitment, opening),
                error::invalid_argument(E_INVALID_CONTRIBUTION),
            );
            let expected_public_key = group::scale_element(
                &session.public_base_element,
                &pedersen_polynomial_commitment::opening_eval_value_p(opening),
            );
            assert!(
                group::element_eq(&public_key, &expected_public_key),
                error::invalid_argument(E_INVALID_REVEALED_SHARE),
            );
        }
    }

    fun verify_public_key_proof(
        session_addr: address,
        purpose: vector<u8>,
        pcs_context: &pedersen_polynomial_commitment::PublicParams,
        pcs_commitment: &pedersen_polynomial_commitment::Commitment,
        public_base_element: &group::Element,
        eval_position: u64,
        public_key: group::Element,
        proof: &sigma_dlog_linear::Proof,
    ): bool {
        let scheme = group::element_scheme(public_base_element);
        if (group::element_scheme(&public_key) != scheme) return false;

        let generator_g = pedersen_polynomial_commitment::generator_g(pcs_context);
        let generator_h = pedersen_polynomial_commitment::generator_h(pcs_context);
        if (group::element_scheme(&generator_g) != scheme || group::element_scheme(&generator_h) != scheme) return false;

        let transcript = vss_transcript(session_addr, purpose, eval_position);
        let b_vals = vector[
            *public_base_element, group::identity(scheme),
            generator_g, generator_h,
        ];
        let p_vals = vector[
            public_key,
            pedersen_polynomial_commitment::commitment_point(pcs_commitment, eval_position),
        ];
        sigma_dlog_linear::verify(&mut transcript, &b_vals, &p_vals, proof)
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

    fun elements_have_scheme(elements: &vector<group::Element>, scheme: u8): bool {
        elements.length() > 0 && elements.map_ref(|e| group::element_scheme(e)).all(|s| *s == scheme)
    }

    // ── Serde helpers ────────────────────────────────────────────────────────

    fun dealer_contribution_0_from_bytes(bytes: vector<u8>): DealerContribution0 {
        let stream = bcs_stream::new(bytes);
        let pcs_commitment = pedersen_polynomial_commitment::deserialize_commitment(&mut stream);
        let private_share_messages = bcs_stream::deserialize_vector(&mut stream, |s| pke::deserialize_ciphertext(s));
        let dealer_state = bcs_stream::deserialize_option(&mut stream, |s| pke::deserialize_ciphertext(s));
        let consistency_proof = bcs_stream::deserialize_option(&mut stream, |s| sigma_dlog_linear::deserialize_proof(s));
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_CONTRIBUTION));
        DealerContribution0 { pcs_commitment, private_share_messages, dealer_state, consistency_proof }
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

    // ── Feature flags/configs begin ─────────────────────────────────────────────────

    const FEATURE__ISSUE154_FIX_FLAG: u64 = 0;

    enum FeatureConfig has copy, drop, store {
        /// Controls whether the dealer should apply the fix for https://github.com/aptos-labs/ace/issues/154.
        Issue154FixFlag,
    }

    entry fun update_issue154_fix_flag(admin: &signer, enabling: bool) {
        assert!(address_of(admin) == @ace, error::permission_denied(E_NOT_ADMIN));
        ensure_feature_slot(admin, FEATURE__ISSUE154_FIX_FLAG);
        let feature_configs = &mut FeatureConfigs[@ace];
        if (enabling) {
            feature_configs.items[FEATURE__ISSUE154_FIX_FLAG] = option::some(FeatureConfig::Issue154FixFlag);
        } else {
            feature_configs.items[FEATURE__ISSUE154_FIX_FLAG] = option::none();
        }
        canonicalize_feature_configs();
    }

    struct FeatureConfigs has copy, drop, key {
        items: vector<Option<FeatureConfig>>,
    }

    #[view]
    public fun feature_configs_bcs(session_addr: address): vector<u8> {
        bcs::to_bytes(&feature_configs_or_empty(session_addr))
    }

    fun ensure_feature_slot(admin: &signer, idx: u64) {
        if (!exists<FeatureConfigs>(@ace)) {
            move_to(admin, FeatureConfigs { items: vector[] });
        };
        let configs = &mut FeatureConfigs[@ace];
        while (configs.items.length() <= idx) {
            configs.items.push_back(option::none());
        };
    }

    fun canonicalize_feature_configs() {
        let is_empty = {
            let configs = &mut FeatureConfigs[@ace];
            while (configs.items.length() > 0) {
                let last_idx = configs.items.length() - 1;
                if (configs.items[last_idx].is_none()) {
                    configs.items.pop_back();
                } else {
                    break;
                };
            };
            configs.items.length() == 0
        };
        if (is_empty) {
            move_from<FeatureConfigs>(@ace);
        }
    }

    fun feature_configs_or_empty(addr: address): FeatureConfigs {
        if (exists<FeatureConfigs>(addr)) {
            *&FeatureConfigs[addr]
        } else {
            FeatureConfigs { items: vector[] }
        }
    }
    // ── Feature flags/configs end ───────────────────────────────────────────────────
}

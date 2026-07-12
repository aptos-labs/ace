/// Distributed Key Re-sharing (DKR) protocol based on https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html.
/// What's done differently: we use a VSS instead of a PVSS.
module ace::dkr {
    use std::bcs;
    use std::error;
    use std::option;
    use std::string::String;
    use std::vector::range;
    use aptos_framework::event;
    use aptos_framework::object::{Self, ExtendRef};
    use ace::dkg;
    use ace::group;
    use ace::pedersen_polynomial_commitment;
    use ace::secret_usage;
    use ace::vss;

    const E_SECRET_SRC_NOT_COMPLETED: u64 = 1;
    const E_INVALID_SECRET_SRC: u64 = 2;
    const E_SECRET_USAGE_GROUP_MISMATCH: u64 = 3;

    /// VSS sessions are being created one per touch().
    const STATE__START_VSSS: u8 = 0;
    const STATE__VSS_IN_PROGRESS: u8 = 1;
    const STATE__CALC_LAGRANGE_COEFFS: u8 = 2;
    const STATE__AGGREGATE_COMMITMENT_POINTS: u8 = 3;
    const STATE__DONE: u8 = 4;
    const STATE__FAIL: u8 = 5;

    struct Session has key {
        caller: address,
        // Has to be a DKG.
        original_session: address,
        // Can be a DKR or a DKG.
        previous_session: address,
        expected_usage: u64,
        note: String,
        current_nodes: vector<address>,
        current_threshold: u64,
        new_nodes: vector<address>,
        new_threshold: u64,
        /// PCS context used for the new committee commitments produced by this DKR.
        pcs_context: pedersen_polynomial_commitment::PublicParams,
        /// PCS context and commitment points for the previous committee shares.
        src_pcs_context: pedersen_polynomial_commitment::PublicParams,
        src_commitment_points: vector<group::Element>,
        src_public_keys: vector<group::Element>,
        state_code: u8,
        vss_sessions: vector<address>,
        vss_contribution_flags: vector<bool>,
        /// Derived from `vss_contribution_flags` once that is finalized.
        /// `vss_contribution_flags == [true, false, true]` ==> `old_eval_points == [1, 3]`.
        lagrange_coeffs_at_zero: vector<group::Scalar>,
        /// Aggregate Pedersen commitment points over the new committee domain {0, 1, ..., n_new}.
        commitment_points: vector<group::Element>,
        /// Aggregate p(i) * G values over the new ACE domain {0, 1, ..., n_new}.
        public_keys: vector<group::Element>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    #[event]
    struct SessionCompleted has drop, store {
        session_addr: address,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        caller: &signer,
        previous_session: address,
        new_nodes: vector<address>,
        new_threshold: u64,
    ): address {
        let is_dkg = dkg::completed(previous_session);
        let is_dkr = completed(previous_session);
        assert!(is_dkg || is_dkr, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        let caller_addr = caller.address_of();
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let extend_ref = object_ref.generate_extend_ref();
        let session_addr = object_ref.address_from_constructor_ref();

        let (original_session, src_pcs_context, src_commitment_points, src_public_keys, current_nodes, current_threshold) = if (is_dkr) {
            params_for_resharing(previous_session)
        } else {
            let (pcs_context, commitment_points, public_keys, nodes, thresh) = dkg::params_for_resharing(previous_session);
            (previous_session, pcs_context, commitment_points, public_keys, nodes, thresh)
        };
        let (expected_usage, note) = if (is_dkr) {
            usage_and_note(previous_session)
        } else {
            dkg::usage_and_note(previous_session)
        };
        let expected_group_scheme = secret_usage::validate_metadata(expected_usage, &note);
        assert!(
            pcs_context_scheme(&src_pcs_context) == expected_group_scheme,
            error::invalid_argument(E_SECRET_USAGE_GROUP_MISMATCH),
        );
        assert!(
            src_commitment_points.length() == current_nodes.length() + 1,
            error::invalid_argument(E_INVALID_SECRET_SRC),
        );
        assert!(
            src_public_keys.length() == current_nodes.length() + 1,
            error::invalid_argument(E_INVALID_SECRET_SRC),
        );

        // Preserve the source PCS context across resharing so the root
        // Pedersen commitment C0 remains stable for the lifetime of a secret.
        // Each original DKG samples its own context; DKR only carries it forward.
        let pcs_context = src_pcs_context;

        // VSS sessions are created lazily via touch() to stay within per-tx gas limits.
        let session = Session {
            caller: caller_addr,
            original_session,
            previous_session,
            expected_usage,
            note,
            current_nodes,
            current_threshold,
            new_nodes,
            new_threshold,
            pcs_context,
            src_pcs_context,
            src_commitment_points,
            src_public_keys,
            state_code: STATE__START_VSSS,
            vss_sessions: vector[],
            vss_contribution_flags: vector[],
            lagrange_coeffs_at_zero: vector[],
            commitment_points: vector[],
            public_keys: vector[],
        };
        move_to(&object_signer, session);
        move_to(&object_signer, SignerStore { extend_ref });
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    #[lint::allow_unsafe_randomness]
    public fun touch(session_addr: address) {
        let session = &mut Session[session_addr];
        if (session.state_code == STATE__START_VSSS) {
            let idx = session.vss_sessions.length();
            if (idx >= session.current_nodes.length()) {
                session.state_code = STATE__VSS_IN_PROGRESS;
                return;
            };
            let signer_store = &SignerStore[session_addr];
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let previous_commitment = vss::previous_commitment_from_parts(
                pedersen_polynomial_commitment::generator_g(&session.src_pcs_context),
                pedersen_polynomial_commitment::generator_h(&session.src_pcs_context),
                session.src_commitment_points[idx + 1],
            );
            let vss_addr = vss::new_session(
                &caller,
                session.current_nodes[idx],
                session.new_nodes,
                session.new_threshold,
                pcs_context_scheme(&session.pcs_context),
                option::some(session.pcs_context),
                option::some(previous_commitment),
            );
            session.vss_sessions.push_back(vss_addr);
        } else if (session.state_code == STATE__VSS_IN_PROGRESS) {
            let vss_completion_flags = session.vss_sessions.map(|sess| vss::completed(sess));
            let num_completed = vss_completion_flags.filter(|flag| *flag).length();
            if (num_completed >= session.current_threshold) {
                session.vss_contribution_flags = vss_completion_flags;
                session.state_code = STATE__CALC_LAGRANGE_COEFFS;
            }
        } else if (session.state_code == STATE__CALC_LAGRANGE_COEFFS) {
            let scheme = pcs_context_scheme(&session.pcs_context);
            let n_old = session.current_nodes.length();
            let old_eval_points = range(0, n_old)
                .filter(|idx_old| session.vss_contribution_flags[*idx_old])
                .map(|idx_old| group::scalar_from_u64(scheme, idx_old + 1));
            session.lagrange_coeffs_at_zero = lagrange_coeffs_at_zero(scheme, &old_eval_points);
            session.state_code = STATE__AGGREGATE_COMMITMENT_POINTS;
        } else if (session.state_code == STATE__AGGREGATE_COMMITMENT_POINTS) {
            let expected_len = session.new_nodes.length() + 1;
            let commitment_idx = session.commitment_points.length();
            if (commitment_idx >= expected_len) {
                session.state_code = STATE__DONE;
                event::emit(SessionCompleted { session_addr });
            } else {
                let n_old = session.current_nodes.length();
                let sub_commitment_points = range(0, n_old)
                    .filter(|idx_old| session.vss_contribution_flags[*idx_old])
                    .map(|idx_old| vss::pcs_commitment_points(session.vss_sessions[idx_old])[commitment_idx]);
                let sub_public_keys = range(0, n_old)
                    .filter(|idx_old| session.vss_contribution_flags[*idx_old])
                    .map(|idx_old| vss::public_keys(session.vss_sessions[idx_old])[commitment_idx]);
                let commitment_point = group::msm(sub_commitment_points, session.lagrange_coeffs_at_zero);
                let public_key = group::msm(sub_public_keys, session.lagrange_coeffs_at_zero);
                if (commitment_idx == 0) {
                    assert!(
                        group::element_eq(&public_key, &session.src_public_keys[0]),
                        error::invalid_argument(E_INVALID_SECRET_SRC),
                    );
                };
                session.commitment_points.push_back(commitment_point);
                session.public_keys.push_back(public_key);
                if (session.commitment_points.length() >= expected_len) {
                    session.state_code = STATE__DONE;
                    event::emit(SessionCompleted { session_addr });
                };
            }
        }
    }

    #[randomness]
    entry fun new_session_entry(caller: &signer, secret_src: address, recipients: vector<address>, threshold: u64) {
        new_session(caller, secret_src, recipients, threshold);
    }

    #[randomness]
    entry fun touch_entry(session_addr: address) {
        touch(session_addr);
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> {
        bcs::to_bytes(&Session[session_addr])
    }

    public fun completed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        Session[session_addr].state_code == STATE__DONE
    }

    public fun failed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        Session[session_addr].state_code == STATE__FAIL
    }

    public fun params_for_resharing(
        secret_src: address,
    ): (
        address,
        pedersen_polynomial_commitment::PublicParams,
        vector<group::Element>,
        vector<group::Element>,
        vector<address>,
        u64,
    ) {
        let session = &Session[secret_src];
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        (
            session.original_session,
            session.pcs_context,
            session.commitment_points,
            session.public_keys,
            session.new_nodes,
            session.new_threshold,
        )
    }

    public fun commitment_points(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        session.commitment_points
    }

    public fun result_pk(session_addr: address): group::Element {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        session.public_keys[0]
    }

    public fun share_pks(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        range(1, session.public_keys.length()).map(|i| session.public_keys[i])
    }

    /// Returns (keypair_id, scheme) for StateViewV0 secret annotations.
    /// keypair_id is the original DKG session that first created this secret lineage.
    public fun keypair_id_and_scheme(addr: address): (address, u8) {
        let s = &Session[addr];
        (s.original_session, pcs_context_scheme(&s.pcs_context))
    }

    public fun keypair_id_scheme_usage_and_note(addr: address): (address, u8, u64, String) {
        let s = &Session[addr];
        (s.original_session, pcs_context_scheme(&s.pcs_context), s.expected_usage, s.note)
    }

    public fun usage_and_note(addr: address): (u64, String) {
        let s = &Session[addr];
        (s.expected_usage, s.note)
    }

    fun pcs_context_scheme(context: &pedersen_polynomial_commitment::PublicParams): u8 {
        let generator_g = pedersen_polynomial_commitment::generator_g(context);
        let generator_h = pedersen_polynomial_commitment::generator_h(context);
        let scheme = group::element_scheme(&generator_g);
        assert!(
            group::element_scheme(&generator_h) == scheme,
            error::invalid_argument(E_SECRET_USAGE_GROUP_MISMATCH),
        );
        scheme
    }

    /// Compute Lagrange interpolation coefficients at x=0 for the given evaluation points.
    /// lagrange[i] = Pi_{j != i} (-evals[j]) / (evals[i] - evals[j])
    fun lagrange_coeffs_at_zero(scheme: u8, evals: &vector<group::Scalar>): vector<group::Scalar> {
        let k = evals.length();
        range(0, k).map(|i| {
            let x_i = &evals[i];
            let num = group::scalar_from_u64(scheme, 1);
            let den = group::scalar_from_u64(scheme, 1);
            range(0, k).for_each(|j| {
                if (j != i) {
                    let x_j = &evals[j];
                    num = group::scalar_mul(&num, &group::scalar_neg(x_j));
                    den = group::scalar_mul(&den, &group::scalar_add(x_i, &group::scalar_neg(x_j)));
                }
            });
            group::scalar_mul(&num, &group::scalar_inv(&den))
        })
    }
}

/// Distributed Key Re-sharing (DKR) protocol based on https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html.
/// What's done differently: we use a VSS instead of a PVSS.
module ace::dkr {
    use ace::dkg;
    use std::bcs;
    use std::error;
    use std::signer::address_of;
    use aptos_framework::object::{Self, ExtendRef};
    use ace::vss;
    use aptos_framework::event;
    use ace::group;
    use std::option;
    use std::vector::range;

    const E_SECRET_SRC_NOT_COMPLETED: u64 = 1;
    const E_INVALID_SECRET_SRC: u64 = 2;

    /// VSS sessions are being created one per touch().
    const STATE__START_VSSS: u8 = 0;
    const STATE__VSS_IN_PROGRESS: u8 = 1;
    const STATE__CALC_LAGRANGE_COEFFS: u8 = 2;
    const STATE__AGGREGATE_SHARE_PKS: u8 = 3;
    const STATE__DONE: u8 = 4;
    const STATE__FAIL: u8 = 5;

    struct Session has key {
        caller: address,
        public_base_element: group::Element,
        secretly_scaled_element: group::Element,
        // Has to be a DKG.
        original_session: address,
        // Can be a DKR or a DKG.
        previous_session: address,
        current_nodes: vector<address>,
        current_threshold: u64,
        new_nodes: vector<address>,
        new_threshold: u64,
        state_code: u8,
        /// Per-current-node share PKs from the previous session, stored here so
        /// touch() can create VSS sessions lazily without re-reading previous_session.
        src_share_pks: vector<group::Element>,
        vss_sessions: vector<address>,
        vss_contribution_flags: vector<bool>,
        /// Derived from `vss_contribution_flags` once that is finalized.
        /// `vss_contribution_flags == [true, false, true]` ==> `old_eval_points == [1, 3]`.
        lagrange_coeffs_at_zero: vector<group::Scalar>,
        share_pks: vector<group::Element>,
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
    public fun new_session(caller: &signer, previous_session: address, new_nodes: vector<address>, new_threshold: u64): address acquires Session {
        let is_dkg = dkg::completed(previous_session);
        let is_dkr = completed(previous_session);
        assert!(is_dkg || is_dkr, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let extend_ref = object_ref.generate_extend_ref();
        let session_addr = object_ref.address_from_constructor_ref();

        // Retrieve source session params and pre-computed old-committee share PKs.
        let (original_session, public_base_element, secretly_scaled_element, current_nodes, current_threshold, src_share_pks) = if (is_dkr) {
            params_for_resharing(previous_session)
        } else {
            let (base_point, pk, nodes, thresh, share_pks) = dkg::params_for_resharing(previous_session);
            (previous_session, base_point, pk, nodes, thresh, share_pks)
        };

        // VSS sessions are created lazily via touch() to stay within per-tx gas limits.
        let session = Session {
            caller: caller_addr,
            original_session,
            previous_session,
            current_nodes,
            current_threshold,
            new_nodes,
            new_threshold,
            public_base_element,
            secretly_scaled_element,
            state_code: STATE__START_VSSS,
            src_share_pks,
            vss_sessions: vector[],
            vss_contribution_flags: vector[],
            lagrange_coeffs_at_zero: vector[],
            share_pks: vector[],
        };
        move_to(&object_signer, session);
        move_to(&object_signer, SignerStore { extend_ref });
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    public fun touch(session_addr: address) acquires Session, SignerStore {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.state_code == STATE__START_VSSS) {
            let idx = session.vss_sessions.length();
            if (idx >= session.current_nodes.length()) {
                session.state_code = STATE__VSS_IN_PROGRESS;
                return;
            };
            let signer_store = borrow_global<SignerStore>(session_addr);
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let vss_addr = vss::new_session(
                &caller,
                session.current_nodes[idx],
                session.new_nodes,
                session.new_threshold,
                session.public_base_element,
                option::some(session.src_share_pks[idx]),
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
            let scheme = group::element_scheme(&session.public_base_element);
            let n_old = session.current_nodes.length();
            let old_eval_points = range(0, n_old)
                .filter(|idx_old| session.vss_contribution_flags[*idx_old])
                .map(|idx_old| group::scalar_from_u64(scheme, idx_old + 1));
            session.lagrange_coeffs_at_zero = lagrange_coeffs_at_zero(scheme, &old_eval_points);
            session.state_code = STATE__AGGREGATE_SHARE_PKS;
        } else if (session.state_code == STATE__AGGREGATE_SHARE_PKS) {
            let n_new = session.new_nodes.length();
            let idx_new = session.share_pks.length();
            if (idx_new >= n_new) {
                session.state_code = STATE__DONE;
                event::emit(SessionCompleted { session_addr });
            } else {
                let n_old = session.current_nodes.length();
                let sub_share_pks: vector<group::Element> = range(0, n_old).filter(|idx_old| session.vss_contribution_flags[*idx_old]).map(|idx_old| vss::share_pks(session.vss_sessions[idx_old])[idx_new]);
                let share_pk = group::msm(sub_share_pks, session.lagrange_coeffs_at_zero);
                session.share_pks.push_back(share_pk);
            }
        }
    }

    #[randomness]
    entry fun new_session_entry(caller: &signer, secret_src: address, recipients: vector<address>, threshold: u64) acquires Session {
        new_session(caller, secret_src, recipients, threshold);
    }

    entry fun touch_entry(session_addr: address) acquires Session, SignerStore {
        touch(session_addr);
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        bcs::to_bytes(borrow_global<Session>(session_addr))
    }

    public fun completed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state_code == STATE__DONE
    }

    public fun failed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state_code == STATE__FAIL
    }

    /// Returns (original_session, base_point, public_key, new_nodes, new_threshold, new_committee_share_pks).
    public fun params_for_resharing(secret_src: address): (address, group::Element, group::Element, vector<address>, u64, vector<group::Element>) acquires Session {
        let session = borrow_global<Session>(secret_src);
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        (session.original_session, session.public_base_element, session.secretly_scaled_element, session.new_nodes, session.new_threshold, session.share_pks)
    }

    public fun share_pks(session_addr: address): vector<group::Element> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        session.share_pks
    }

    /// Returns (keypair_id, scheme) for StateViewV0 secret annotations.
    /// keypair_id is the original DKG session that first created this secret lineage.
    public fun keypair_id_and_scheme(addr: address): (address, u8) {
        let s = &Session[addr];
        (s.original_session, group::element_scheme(&s.public_base_element))
    }

    /// Compute Lagrange interpolation coefficients at x=0 for the given evaluation points.
    /// lagrange[i] = Π_{j ≠ i} (-evals[j]) / (evals[i] - evals[j])
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

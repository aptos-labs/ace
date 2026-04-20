/// Distributed Key Re-sharing (DKR) protocol based on https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html.
/// What's done differently: we use a VSS instead of a PVSS.
module ace::dkr {
    use ace::dkg;
    use std::bcs;
    use std::error;
    use std::signer::address_of;
    use aptos_framework::object;
    use ace::vss;
    use aptos_framework::event;
    use ace::group;
    use std::option;

    const E_SECRET_SRC_NOT_COMPLETED: u64 = 1;
    const E_INVALID_SECRET_SRC: u64 = 2;
    
    const STATE__IN_PROGRESS: u8 = 0;
    const STATE__DONE: u8 = 1;
    const STATE__FAIL: u8 = 2;

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
        vss_sessions: vector<address>,
        vss_contribution_flags: vector<bool>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(caller: &signer, previous_session: address, new_nodes: vector<address>, new_threshold: u64): address {
        let is_dkg = dkg::completed(previous_session);
        let is_dkr = completed(previous_session);
        assert!(is_dkg || is_dkr, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();
        let (original_session, public_base_element, secretly_scaled_element, current_nodes, current_threshold) = if (is_dkr) {
            params_for_resharing(previous_session)
        } else {
            let (base_point, pk, current_nodes, current_threshold) = dkg::params_for_resharing(previous_session);
            (previous_session, base_point, pk, current_nodes, current_threshold)
        };
        let scheme = group::element_scheme(&public_base_element);
        let share_pks: vector<option::Option<group::Element>> = if (is_dkg) {
            // Compute per-worker share verification keys from DKG Feldman commitments.
            // Worker j (0-indexed) has eval point j+1. Their share PK:
            //   pk_j = Σ_{k: done_flags[k]} eval_feldman(vss_sessions[k], j+1)
            let (dkg_vss_sessions, done_flags) = dkg::vss_sessions_and_done_flags(previous_session);
            let n = current_nodes.length();
            let result = vector[];
            let j = 0u64;
            while (j < n) {
                let x = group::scalar_from_u64(scheme, j + 1);
                let pk_parts = vector[];
                let k = 0u64;
                while (k < dkg_vss_sessions.length()) {
                    if (done_flags[k]) {
                        let points = vss::pcs_commitment_points(dkg_vss_sessions[k]);
                        pk_parts.push_back(feldman_eval_horner(&points, &x));
                    };
                    k += 1;
                };
                result.push_back(option::some(group::element_sum(&pk_parts)));
                j += 1;
            };
            result
        } else {
            // DKR-from-DKR: per-worker share PKs require Lagrange-weighted Feldman evaluation.
            // Simplified: skip sigma proof for this resharing step.
            let n = current_nodes.length();
            let result = vector[];
            let j = 0u64;
            while (j < n) {
                result.push_back(option::none());
                j += 1;
            };
            result
        };
        let vss_sessions = vector[];
        let j2 = 0u64;
        while (j2 < current_nodes.length()) {
            let share_holder = current_nodes[j2];
            let vss_addr = vss::new_session(
                caller,
                share_holder,
                new_nodes,
                new_threshold,
                public_base_element,
                share_pks[j2],
            );
            vss_sessions.push_back(vss_addr);
            j2 += 1;
        };
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
            state_code: STATE__IN_PROGRESS,
            vss_sessions,
            vss_contribution_flags: vector[],
        };
        move_to(&object_signer, session);
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    public fun touch(session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.state_code == STATE__IN_PROGRESS) {
            let vss_completion_flags = session.vss_sessions.map(|sess| vss::completed(sess));
            let num_completed = vss_completion_flags.filter(|flag| *flag).length();
            if (num_completed >= session.current_threshold) {
                session.vss_contribution_flags = vss_completion_flags;
                session.state_code = STATE__DONE;
            }
        }
    }

    #[randomness]
    entry fun new_session_entry(caller: &signer, secret_src: address, recipients: vector<address>, threshold: u64) {
        new_session(caller, secret_src, recipients, threshold);
    }

    entry fun touch_entry(session_addr: address) acquires Session {
        touch(session_addr);
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        bcs::to_bytes(borrow_global<Session>(session_addr))
    }

    public fun completed(session_addr: address): bool  {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state_code == STATE__DONE
    }

    public fun failed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state_code == STATE__FAIL
    }

    /// Returns the original session, the base point, the public key, the new nodes, and the new threshold.
    public fun params_for_resharing(secret_src: address): (address, group::Element, group::Element, vector<address>, u64) {
        let session = borrow_global<Session>(secret_src);
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SECRET_SRC_NOT_COMPLETED));
        (session.original_session, session.public_base_element, session.secretly_scaled_element, session.new_nodes, session.new_threshold)
    }

    /// Evaluate a Feldman polynomial at scalar x using Horner's method.
    /// eval = points[0] + x*points[1] + x^2*points[2] + ...
    fun feldman_eval_horner(points: &vector<group::Element>, x: &group::Scalar): group::Element {
        let t = points.length();
        assert!(t > 0, error::invalid_argument(E_INVALID_SECRET_SRC));
        let i = t;
        let eval = points[t - 1];
        while (i > 1) {
            i -= 1;
            eval = group::element_add(&group::scale_element(&eval, x), points.borrow(i - 1));
        };
        eval
    }
}

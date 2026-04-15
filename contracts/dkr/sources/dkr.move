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
        let vss_sessions = current_nodes.map(|share_holder| {
            vss::new_session(caller, share_holder, new_nodes, new_threshold, public_base_element)
            // TODO(AI should ignore): dealer in this VSS should prove the secret being dealt is an expected one, not a random one.
        });
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

    public entry fun new_session_entry(caller: &signer, secret_src: address, recipients: vector<address>, threshold: u64) {
        new_session(caller, secret_src, recipients, threshold);
    }

    public entry fun touch_entry(session_addr: address) acquires Session {
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

    // fun contains_all_1_submatrix(matrix: vector<vector<u8>>, num_rows: u64, num_cols: u64): bool {
    //     //TODO
    //     false
    // }
}

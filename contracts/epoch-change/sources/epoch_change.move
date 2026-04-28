module ace::epoch_change {
    use ace::dkr;
    use std::option::{Option, Self};
    use aptos_framework::object::{Self, ExtendRef};
    use ace::dkg;
    use ace::group;
    use std::error;
    use std::signer::address_of;

    const E_SESSION_NOT_COMPLETED: u64 = 1;

    const STATE__START_DKRS: u8 = 0;
    const STATE__AWAIT_SUBSESSION_COMPLETION: u8 = 1;
    const STATE__DONE: u8 = 2;

    struct Session has key {
        caller: address,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
        nxt_epoch_duration_micros: u64,
        secrets_to_reshare: vector<address>,
        state_code: u8,
        dkg: Option<address>,
        dkrs: vector<address>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        caller: &signer,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
        nxt_epoch_duration_micros: u64,
        secrets_to_reshare: vector<address>,
        new_secret_scheme: Option<u8>,
    ): address {
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let extend_ref = object_ref.generate_extend_ref();
        let session_addr = object_ref.address_from_constructor_ref();

        let dkg = if (new_secret_scheme.is_some()) {
            let addr = dkg::new_session(caller, nxt_nodes, nxt_threshold, group::rand_element(new_secret_scheme.destroy_some()));
            option::some(addr)
        } else {
            option::none()
        };

        let session = Session {
            caller: caller_addr,
            cur_nodes,
            cur_threshold,
            nxt_nodes,
            nxt_threshold,
            nxt_epoch_duration_micros,
            secrets_to_reshare,
            state_code: STATE__START_DKRS,
            dkg,
            dkrs: vector[],
        };

        move_to(&object_signer, session);
        move_to(&object_signer, SignerStore {
            extend_ref,
        });

        session_addr
    }

    entry fun touch(session_addr: address) {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.state_code == STATE__START_DKRS) {
            let idx = session.dkrs.length();
            if (idx >= session.secrets_to_reshare.length()) {
                session.state_code = STATE__AWAIT_SUBSESSION_COMPLETION;
                return;
            };
            let signer_store = borrow_global<SignerStore>(session_addr);
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let dkr = dkr::new_session(&caller, session.secrets_to_reshare[idx], session.nxt_nodes, session.nxt_threshold);
            session.dkrs.push_back(dkr);
        } else if (session.state_code == STATE__AWAIT_SUBSESSION_COMPLETION) {
            let all_dkr_completed = session.dkrs.all(|dkr| dkr::completed(*dkr));
            let all_dkg_completed = session.dkg.is_none() || dkg::completed(*session.dkg.borrow());
            if (all_dkr_completed && all_dkg_completed) {
                session.state_code = STATE__DONE;
            }
        }
    }

    public fun completed(session_addr: address): bool {
        let session = borrow_global<Session>(session_addr);
        session.state_code == STATE__DONE
    }

    /// Returns (nxt_nodes, nxt_threshold) for external view composition (e.g. network::state_view_v0_bcs).
    public fun nxt_nodes_and_threshold(session_addr: address): (vector<address>, u64) acquires Session {
        let session = borrow_global<Session>(session_addr);
        (session.nxt_nodes, session.nxt_threshold)
    }

    /// Assuming session is completed, returns:
    /// - new epoch nodes
    /// - new epoch threshold
    /// - new secrets
    /// - new epoch duration
    public fun results(session_addr: address): (vector<address>, u64, vector<address>, u64) {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state_code == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        let secrets = session.dkrs;
        if (session.dkg.is_some()) {
            secrets.push_back(*session.dkg.borrow());
        };
        (session.nxt_nodes, session.nxt_threshold, secrets, session.nxt_epoch_duration_micros)
    }
}

/// Distributed Key Generation (DKG) contract.
///
/// ## Client implementation guide
///
/// A DKG client needs the following starting parameters.
/// - worker_account_addr, worker_account_sk, and worker_pke_dk: necessary credentials.
/// - session_addr: this identifies which DKG session to work on.
/// - term_rx: this allows upper-level apps to send stop cmd.
///
/// The main logic is the following.
/// - It should "touch" the session (trigger any due update and fetch the latest state) every 5 secs.
/// - Every time we fetch the latest state `session`, we:
///   - first ensure it is still in progress and we are one of the workers (Otherwise, we shutdown all sub-clients then stop ourselves);
///   - ensure the vss client for each `session.vss_sessions` is running:
///     - start it, if we haven't done that in this dkg client run (and hold the corresponding term_tx tight);
///     - stop any vss client if they are running but the "role + address" is not specified in `session.vss_sessions`.
/// - Here is how (role + address) is specified in the session state: if our index in the worker list is `my_idx`, then our vss role in `vss_sessions[my_idx]` is dealer, otherwise, we are a recipient.
/// - Our vss clients are supposed to be reentrant-safe. So should our dkg client.
module ace::dkg {

    use ace::vss;
    use ace::group;
    use std::option::{Option, Self};
    use aptos_framework::event;
    use aptos_framework::object;
    use std::signer::address_of;
    use std::error;
    use std::bcs;

    const STATE__VSS_IN_PROGRESS: u8 = 0;
    const STATE__DONE: u8 = 1;
    const STATE__FAIL: u8 = 2;

    const E_ONLY_CALLER_CAN_DO_THIS: u64 = 1;

    struct Session has key {
        caller: address,
        workers: vector<address>,
        threshold: u64,
        base_point: group::Element,
        state: u8,
        vss_sessions: vector<address>,
        /// When we try to conclude this DKG session with enough VSS done, some other may not have finished yet and will thus be ignored.
        done_flags: vector<bool>,
        result_pk: Option<group::Element>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    public fun new_session(caller: &signer, workers: vector<address>, threshold: u64, base_point: group::Element): address {
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let session_addr = object_ref.address_from_constructor_ref();
        let vss_sessions = workers.map(|worker| vss::new_session(caller, worker, workers, threshold, base_point));
        let session = Session {
            caller: caller_addr,
            workers,
            threshold,
            base_point,
            state: STATE__VSS_IN_PROGRESS,
            vss_sessions,
            done_flags: vector[],
            result_pk: option::none(),
        };
        move_to(&object_signer, session);
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    public entry fun new_session_entry(caller: &signer, workers: vector<address>, threshold: u64, base_point_bytes: vector<u8>) {
        let base_point = group::element_from_bytes(base_point_bytes);
        new_session(caller, workers, threshold, base_point);
    }

    #[event]
    struct SessionTouched has drop, store {
        session_addr: address,
        session_bcs: vector<u8>,
    }

    public fun touch(session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.state == STATE__VSS_IN_PROGRESS) {
            // if t or more sessions are done, we can finalize the aggregated public key
            let done_flags = vector[];
            let num_done = 0;
            let done_sessions = vector[];
            session.vss_sessions.for_each(|vss_session| {
                let done = vss::completed(vss_session);
                if (done) {
                    num_done += 1;
                    done_sessions.push_back(vss_session);
                };
                done_flags.push_back(done);

            });
            if (num_done >= session.threshold) {
                let available_sub_pks = done_sessions.map(|vss_session| vss::result_pk(vss_session));
                session.done_flags = done_flags;
                session.result_pk = option::some(group::element_sum(&available_sub_pks));
                session.state = STATE__DONE;
            }
        };
        event::emit(SessionTouched {
            session_addr,
            session_bcs: bcs::to_bytes(session),
        });
    }

    public fun cancel(caller: &signer, session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.caller != address_of(caller)) {
            abort error::permission_denied(E_ONLY_CALLER_CAN_DO_THIS);
        };
        session.state = STATE__FAIL;
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        bcs::to_bytes(borrow_global<Session>(session_addr))
    }

    public entry fun touch_entry(session_addr: address) acquires Session {
        touch(session_addr);
    }
}

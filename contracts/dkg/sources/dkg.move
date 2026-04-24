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
/// - It should "touch" the session (trigger any due update and fetch the latest state) every 1 sec.
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
    use aptos_framework::object::{Self, ExtendRef};
    use std::signer::address_of;
    use std::error;
    use std::bcs;
    use std::vector::range;

    /// VSS sessions are being created one per touch().
    const STATE__START_VSSS: u8 = 0;
    /// All VSS sessions exist; waiting for threshold of them to complete.
    const STATE__VSS_IN_PROGRESS: u8 = 1;
    /// Threshold VSS sessions are done; aggregating per-worker share PKs one per touch().
    const STATE__AGGREGATE_SHARE_PKS: u8 = 2;
    const STATE__DONE: u8 = 3;
    const STATE__FAIL: u8 = 4;

    const E_ONLY_CALLER_CAN_DO_THIS: u64 = 1;
    const E_SESSION_NOT_COMPLETED: u64 = 2;

    struct Session has key {
        caller: address,
        workers: vector<address>,
        threshold: u64,
        public_base_element: group::Element,
        state: u8,
        vss_sessions: vector<address>,
        /// Which VSS sessions contributed when we finalised. Empty until state >= AGGREGATE_SHARE_PKS.
        done_flags: vector<bool>,
        secretly_scaled_element: Option<group::Element>,
        /// Per-worker share PKs: share_pks[j] = Σ_{k: contributing} vss_k.share_pks[j].
        /// Built one entry per touch() in AGGREGATE_SHARE_PKS; complete when state == DONE.
        share_pks: vector<group::Element>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(caller: &signer, workers: vector<address>, threshold: u64, public_base_element: group::Element): address {
        let caller_addr = address_of(caller);
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let extend_ref = object_ref.generate_extend_ref();
        let session_addr = object_ref.address_from_constructor_ref();
        // VSS sessions are created lazily, one per touch(), to stay within per-tx gas limits.
        let session = Session {
            caller: caller_addr,
            workers,
            threshold,
            public_base_element,
            state: STATE__START_VSSS,
            vss_sessions: vector[],
            done_flags: vector[],
            secretly_scaled_element: option::none(),
            share_pks: vector[],
        };
        move_to(&object_signer, session);
        move_to(&object_signer, SignerStore { extend_ref });
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    #[randomness]
    entry fun new_session_entry(caller: &signer, workers: vector<address>, threshold: u64, base_point_bytes: vector<u8>) {
        let base_point = group::element_from_bytes(base_point_bytes);
        new_session(caller, workers, threshold, base_point);
    }

    #[event]
    struct SessionTouched has drop, store {
        session_addr: address,
        session_bcs: vector<u8>,
    }

    public fun touch(session_addr: address) acquires Session, SignerStore {
        let session = borrow_global_mut<Session>(session_addr);
        if (session.state == STATE__START_VSSS) {
            let idx = session.vss_sessions.length();
            if (idx >= session.workers.length()) {
                session.state = STATE__VSS_IN_PROGRESS;
                return;
            };
            let signer_store = borrow_global<SignerStore>(session_addr);
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let vss_addr = vss::new_session(
                &caller,
                session.workers[idx],   // dealer
                session.workers,        // recipients
                session.threshold,
                session.public_base_element,
                option::none(),
            );
            session.vss_sessions.push_back(vss_addr);
        } else if (session.state == STATE__VSS_IN_PROGRESS) {
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
                session.secretly_scaled_element = option::some(group::element_sum(&available_sub_pks));
                session.state = STATE__AGGREGATE_SHARE_PKS;
            }
        } else if (session.state == STATE__AGGREGATE_SHARE_PKS) {
            let n = session.workers.length();
            let j = session.share_pks.length();
            if (j >= n) {
                session.state = STATE__DONE;
            } else {
                // One share PK per touch: sum contributing VSS share_pks for worker j.
                let n_vss = session.vss_sessions.length();
                let sub_share_pks = range(0, n_vss)
                    .filter(|i| session.done_flags[*i])
                    .map(|i| vss::share_pks(session.vss_sessions[i])[j]);
                session.share_pks.push_back(group::element_sum(&sub_share_pks));
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

    public fun completed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state == STATE__DONE
    }

    public fun failed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        borrow_global<Session>(session_addr).state == STATE__FAIL
    }

    public fun params_for_resharing(session_addr: address): (group::Element, group::Element, vector<address>, u64, vector<group::Element>) acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        (session.public_base_element, *session.secretly_scaled_element.borrow(), session.workers, session.threshold, session.share_pks)
    }

    public fun share_pks(session_addr: address): vector<group::Element> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        session.share_pks
    }

    /// Returns (vss_sessions, done_flags) for the DKG session.
    /// Used by DKR to compute per-worker share verification keys.
    public fun vss_sessions_and_done_flags(session_addr: address): (vector<address>, vector<bool>) acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        (session.vss_sessions, session.done_flags)
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> acquires Session {
        bcs::to_bytes(borrow_global<Session>(session_addr))
    }

    entry fun touch_entry(session_addr: address) acquires Session, SignerStore {
        touch(session_addr);
    }
}

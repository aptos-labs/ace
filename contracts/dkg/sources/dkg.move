/// Distributed Key Generation (DKG) contract.
///
/// ## Client implementation guide
///
/// A DKG client needs the following starting parameters.
/// - worker_account_addr, worker_account_sk, worker_pke_dk, worker_sig_sk, and a persistent VSS store.
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

    use std::bcs;
    use std::error;
    use std::option;
    use std::string::String;
    use std::vector::range;
    use aptos_framework::event;
    use aptos_framework::object::{Self, ExtendRef};
    use ace::group;
    use ace::pedersen_polynomial_commitment;
    use ace::secret_usage;
    use ace::vss;

    /// VSS sessions are being created one per touch().
    const STATE__START_VSSS: u8 = 0;
    /// All VSS sessions exist; waiting for threshold of them to complete.
    const STATE__VSS_IN_PROGRESS: u8 = 1;
    /// Threshold VSS sessions are done; aggregating PCS commitment points one per touch().
    const STATE__AGGREGATE_COMMITMENT_POINTS: u8 = 2;
    const STATE__DONE: u8 = 3;
    const STATE__FAIL: u8 = 4;

    const E_ONLY_CALLER_CAN_DO_THIS: u64 = 1;
    const E_SESSION_NOT_COMPLETED: u64 = 2;
    const E_SECRET_USAGE_GROUP_MISMATCH: u64 = 3;

    struct Session has key {
        caller: address,
        workers: vector<address>,
        threshold: u64,
        scheme: u8,
        pcs_context: pedersen_polynomial_commitment::PublicParams,
        expected_usage: u64,
        note: String,
        state: u8,
        vss_sessions: vector<address>,
        /// Which VSS sessions contributed when we finalised. Empty until state >= AGGREGATE_COMMITMENT_POINTS.
        done_flags: vector<bool>,
        /// Aggregate Pedersen commitment points over the ACE domain {0, 1, ..., n}.
        ///
        /// commitment_points[j] = Σ_{k: contributing} vss_k.commitment_points[j].
        /// Built one entry per touch() in AGGREGATE_COMMITMENT_POINTS; complete when state == DONE.
        commitment_points: vector<group::Element>,
        /// Aggregate p(i) * G values over the ACE domain {0, 1, ..., n}.
        public_keys: vector<group::Element>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        caller: &signer,
        workers: vector<address>,
        threshold: u64,
        scheme: u8,
        expected_usage: u64,
        note: String,
    ): address {
        let expected_group_scheme = secret_usage::validate_metadata(expected_usage, &note);
        assert!(
            scheme == expected_group_scheme,
            error::invalid_argument(E_SECRET_USAGE_GROUP_MISMATCH),
        );

        let caller_addr = caller.address_of();
        let object_ref = object::create_sticky_object(caller_addr);
        let object_signer = object_ref.generate_signer();
        let extend_ref = object_ref.generate_extend_ref();
        let session_addr = object_ref.address_from_constructor_ref();
        let pcs_context = pedersen_polynomial_commitment::new_context(scheme);
        // VSS sessions are created lazily, one per touch(), to stay within per-tx gas limits.
        let session = Session {
            caller: caller_addr,
            workers,
            threshold,
            scheme,
            pcs_context,
            expected_usage,
            note,
            state: STATE__START_VSSS,
            vss_sessions: vector[],
            done_flags: vector[],
            commitment_points: vector[],
            public_keys: vector[],
        };
        move_to(&object_signer, session);
        move_to(&object_signer, SignerStore { extend_ref });
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    #[randomness]
    entry fun new_session_entry(
        caller: &signer,
        workers: vector<address>,
        threshold: u64,
        scheme: u8,
        expected_usage: u64,
        note: String,
    ) {
        new_session(caller, workers, threshold, scheme, expected_usage, note);
    }

    #[event]
    struct SessionTouched has drop, store {
        session_addr: address,
        session_bcs: vector<u8>,
    }

    #[lint::allow_unsafe_randomness]
    public fun touch(session_addr: address) {
        let session = &mut Session[session_addr];
        if (session.state == STATE__START_VSSS) {
            let idx = session.vss_sessions.length();
            if (idx >= session.workers.length()) {
                session.state = STATE__VSS_IN_PROGRESS;
                return;
            };
            let signer_store = &SignerStore[session_addr];
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let vss_addr = vss::new_session(
                &caller,
                session.workers[idx],
                session.workers,
                session.threshold,
                session.scheme,
                option::some(session.pcs_context),
                option::none(),
            );
            session.vss_sessions.push_back(vss_addr);
        } else if (session.state == STATE__VSS_IN_PROGRESS) {
            let done_flags = vector[];
            let num_done = 0;
            session.vss_sessions.for_each(|vss_session| {
                let done = vss::completed(vss_session);
                if (done) {
                    num_done += 1;
                };
                done_flags.push_back(done);
            });
            if (num_done >= session.threshold) {
                session.done_flags = done_flags;
                session.state = STATE__AGGREGATE_COMMITMENT_POINTS;
            }
        } else if (session.state == STATE__AGGREGATE_COMMITMENT_POINTS) {
            let expected_len = session.workers.length() + 1;
            let commitment_idx = session.commitment_points.length();
            if (commitment_idx >= expected_len) {
                session.state = STATE__DONE;
            } else {
                let n_vss = session.vss_sessions.length();
                let points = range(0, n_vss)
                    .filter(|i| session.done_flags[*i])
                    .map(|i| vss::pcs_commitment_points(session.vss_sessions[i])[commitment_idx]);
                let public_keys = range(0, n_vss)
                    .filter(|i| session.done_flags[*i])
                    .map(|i| vss::public_keys(session.vss_sessions[i])[commitment_idx]);
                session.commitment_points.push_back(group::element_sum(&points));
                session.public_keys.push_back(group::element_sum(&public_keys));
                if (session.commitment_points.length() >= expected_len) {
                    session.state = STATE__DONE;
                };
            }
        };
        event::emit(SessionTouched {
            session_addr,
            session_bcs: bcs::to_bytes(session),
        });
    }

    public fun cancel(caller: &signer, session_addr: address) {
        let session = &mut Session[session_addr];
        if (session.caller != caller.address_of()) {
            abort error::permission_denied(E_ONLY_CALLER_CAN_DO_THIS);
        };
        session.state = STATE__FAIL;
    }

    public fun completed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        Session[session_addr].state == STATE__DONE
    }

    public fun failed(session_addr: address): bool {
        if (!exists<Session>(session_addr)) return false;
        Session[session_addr].state == STATE__FAIL
    }

    public fun params_for_resharing(
        session_addr: address,
    ): (
        pedersen_polynomial_commitment::PublicParams,
        vector<group::Element>,
        vector<group::Element>,
        vector<address>,
        u64,
    ) {
        let session = &Session[session_addr];
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        (session.pcs_context, session.commitment_points, session.public_keys, session.workers, session.threshold)
    }

    public fun commitment_points(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        session.commitment_points
    }

    public fun result_pk(session_addr: address): group::Element {
        let session = &Session[session_addr];
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        session.public_keys[0]
    }

    public fun share_pks(session_addr: address): vector<group::Element> {
        let session = &Session[session_addr];
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        range(1, session.public_keys.length()).map(|i| session.public_keys[i])
    }

    /// Returns (vss_sessions, done_flags) for the DKG session.
    /// Used by DKR to reconstruct the contributing set.
    public fun vss_sessions_and_done_flags(session_addr: address): (vector<address>, vector<bool>) {
        let session = &Session[session_addr];
        assert!(session.state == STATE__DONE, error::invalid_argument(E_SESSION_NOT_COMPLETED));
        (session.vss_sessions, session.done_flags)
    }

    public fun is_session(addr: address): bool {
        exists<Session>(addr)
    }

    /// Returns (keypair_id, scheme) for StateViewV0 secret annotations.
    /// For a DKG session, the keypair_id IS the session address (it is the origin).
    public fun keypair_id_and_scheme(addr: address): (address, u8) {
        let s = &Session[addr];
        (addr, s.scheme)
    }

    public fun keypair_id_scheme_usage_and_note(addr: address): (address, u8, u64, String) {
        let s = &Session[addr];
        (addr, s.scheme, s.expected_usage, s.note)
    }

    public fun usage_and_note(addr: address): (u64, String) {
        let s = &Session[addr];
        (s.expected_usage, s.note)
    }

    #[view]
    public fun get_session_bcs(session_addr: address): vector<u8> {
        bcs::to_bytes(&Session[session_addr])
    }

    #[randomness]
    entry fun touch_entry(session_addr: address) {
        touch(session_addr);
    }
}

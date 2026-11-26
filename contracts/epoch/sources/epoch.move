/// One epoch's on-chain lifecycle. Two Session objects coexist during a handoff:
/// the old epoch is HANDOFF while the new epoch is INIT, then the new epoch is
/// SERVING while the old epoch is GRACE. Both refer to the same epoch_change
/// session through outbound_transition and inbound_transition, respectively.
module ace::epoch {
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use std::bcs;
    use std::error;
    use std::option::{Self, Option};
    use std::vector::range;
    use ace::epoch_change;

    const E_ONLY_CONTROLLER: u64 = 1;
    const E_WRONG_PHASE: u64 = 2;
    const E_INVALID_COMMITTEE: u64 = 3;
    const E_INVALID_TRANSITION: u64 = 4;
    const E_NOT_READY: u64 = 5;
    const E_NOT_MEMBER: u64 = 6;
    const E_GRACE_NOT_EXPIRED: u64 = 7;
    const E_INVALID_DURATION: u64 = 8;

    const INIT: u8 = 0;
    const SERVING: u8 = 1;
    const HANDOFF: u8 = 2;
    const GRACE: u8 = 3;
    const FINISHED: u8 = 4;

    const MIN_EPOCH_DURATION_MICROS: u64 = 30_000_000;
    const GRACE_DURATION_MICROS: u64 = 60_000_000;

    struct Session has key {
        /// Address of the network-controlled object signer authorized to mutate stages.
        controller: address,
        epoch: u64,
        phase: u8,
        nodes: vector<address>,
        threshold: u64,
        admin_multisig: address,
        /// Current DKG/DKR session addresses. Populated when INIT enters SERVING.
        secrets: vector<address>,
        /// Feature bits for this epoch; active when this Session enters SERVING.
        features: u64,
        epoch_duration_micros: u64,
        serving_since_micros: u64,
        /// Shared epoch_change session that creates this epoch, including E0.
        inbound_transition: Option<address>,
        /// Shared epoch_change session used to create this epoch's successor.
        outbound_transition: Option<address>,
        grace_until_micros: u64,
        /// A node sets its own bit only after its next-epoch shares are ready.
        ready_nodes: vector<bool>,
    }

    /// Create an INIT epoch after its shared inbound epoch_change session exists.
    /// For E0, the inbound session has no current nodes or retained secrets.
    public fun new_session(
        controller: &signer,
        epoch: u64,
        nodes: vector<address>,
        threshold: u64,
        admin_multisig: address,
        epoch_duration_micros: u64,
        features: u64,
        inbound_transition: address,
    ): address {
        validate_committee(&nodes, threshold);
        assert!(epoch_duration_micros >= MIN_EPOCH_DURATION_MICROS, error::invalid_argument(E_INVALID_DURATION));
        let (transition_nodes, transition_threshold) = epoch_change::nxt_nodes_and_threshold(inbound_transition);
        assert!(transition_nodes == nodes && transition_threshold == threshold, error::invalid_argument(E_INVALID_TRANSITION));

        let object_ref = object::create_sticky_object(controller.address_of());
        let epoch_addr = object_ref.address_from_constructor_ref();
        let epoch_signer = object_ref.generate_signer();
        move_to(&epoch_signer, Session {
            controller: controller.address_of(),
            epoch,
            phase: INIT,
            nodes,
            threshold,
            admin_multisig,
            secrets: vector[],
            features,
            epoch_duration_micros,
            serving_since_micros: 0,
            inbound_transition: option::some(inbound_transition),
            outbound_transition: option::none(),
            grace_until_micros: 0,
            ready_nodes: range(0, transition_nodes.length()).map(|_| false),
        });
        epoch_addr
    }

    /// The serving epoch begins one outbound transition. The successor's INIT
    /// Session must point to the same epoch_change session.
    public fun begin_handoff(controller: &signer, epoch_addr: address, transition: address) {
        let session = &mut Session[epoch_addr];
        assert_controller(controller, session);
        assert!(session.phase == SERVING, error::invalid_state(E_WRONG_PHASE));
        assert!(session.outbound_transition.is_none(), error::invalid_state(E_WRONG_PHASE));
        assert!(transition != @0x0, error::invalid_argument(E_INVALID_TRANSITION));
        session.outbound_transition = option::some(transition);
        session.phase = HANDOFF;
    }

    /// Signed readiness claim for a new epoch. The node must first reconstruct
    /// and verify every next-epoch share and ensure its handler can serve them.
    public entry fun acknowledge_ready(node: &signer, epoch_addr: address) {
        let session = &mut Session[epoch_addr];
        assert!(session.phase == INIT, error::invalid_state(E_WRONG_PHASE));
        let inbound = *session.inbound_transition.borrow();
        assert!(epoch_change::completed(inbound), error::invalid_state(E_NOT_READY));
        let (found, idx) = session.nodes.index_of(&node.address_of());
        assert!(found, error::permission_denied(E_NOT_MEMBER));
        session.ready_nodes[idx] = true;
    }

    public fun ready_to_serve(epoch_addr: address): bool {
        let session = &Session[epoch_addr];
        if (session.phase != INIT || session.inbound_transition.is_none()) return false;
        let inbound = *session.inbound_transition.borrow();
        if (!epoch_change::completed(inbound)) return false;
        let ready_count = session.ready_nodes.filter(|ready| *ready).length();
        ready_count >= session.threshold
    }

    /// Complete INIT using the results of its inbound transition. Network calls
    /// this and begin_grace(old) in one transaction, switching their pointers
    /// atomically. E0 has no old epoch and therefore no begin_grace call.
    public fun begin_serving(controller: &signer, epoch_addr: address) {
        assert!(ready_to_serve(epoch_addr), error::invalid_state(E_NOT_READY));
        let session = &mut Session[epoch_addr];
        assert_controller(controller, session);
        let inbound = *session.inbound_transition.borrow();
        let (nodes, threshold, secrets, duration_micros) = epoch_change::results(inbound);
        assert!(nodes == session.nodes && threshold == session.threshold, error::invalid_argument(E_INVALID_TRANSITION));
        assert!(duration_micros == session.epoch_duration_micros, error::invalid_argument(E_INVALID_DURATION));
        session.secrets = secrets;
        session.serving_since_micros = timestamp::now_microseconds();
        session.phase = SERVING;
    }

    /// Retain every old-epoch secret for exactly 60 seconds after the successor
    /// starts serving. Network calls this in the same transaction as successor
    /// begin_serving, so both epoch stages change atomically.
    public fun begin_grace(controller: &signer, epoch_addr: address) {
        let session = &mut Session[epoch_addr];
        assert_controller(controller, session);
        assert!(session.phase == HANDOFF, error::invalid_state(E_WRONG_PHASE));
        session.grace_until_micros = timestamp::now_microseconds() + GRACE_DURATION_MICROS;
        session.phase = GRACE;
    }

    public fun grace_expired(epoch_addr: address): bool {
        let session = &Session[epoch_addr];
        session.phase == GRACE && timestamp::now_microseconds() >= session.grace_until_micros
    }

    public fun finish_grace(controller: &signer, epoch_addr: address) {
        let session = &mut Session[epoch_addr];
        assert_controller(controller, session);
        assert!(session.phase == GRACE, error::invalid_state(E_WRONG_PHASE));
        assert!(timestamp::now_microseconds() >= session.grace_until_micros, error::invalid_state(E_GRACE_NOT_EXPIRED));
        session.phase = FINISHED;
    }

    #[view]
    public fun get_session_bcs(epoch_addr: address): vector<u8> {
        bcs::to_bytes(&Session[epoch_addr])
    }

    #[view]
    public fun phase(epoch_addr: address): u8 {
        Session[epoch_addr].phase
    }

    public fun epoch(epoch_addr: address): u64 {
        Session[epoch_addr].epoch
    }

    public fun nodes_threshold_secrets(epoch_addr: address): (vector<address>, u64, vector<address>) {
        let session = &Session[epoch_addr];
        (session.nodes, session.threshold, session.secrets)
    }

    public fun admin_multisig(epoch_addr: address): address {
        Session[epoch_addr].admin_multisig
    }

    public fun features(epoch_addr: address): u64 {
        Session[epoch_addr].features
    }

    public fun epoch_duration_micros(epoch_addr: address): u64 {
        Session[epoch_addr].epoch_duration_micros
    }

    public fun serving_since_micros(epoch_addr: address): u64 {
        Session[epoch_addr].serving_since_micros
    }

    public fun inbound_transition(epoch_addr: address): Option<address> {
        Session[epoch_addr].inbound_transition
    }

    public fun outbound_transition(epoch_addr: address): Option<address> {
        Session[epoch_addr].outbound_transition
    }

    public fun grace_until_micros(epoch_addr: address): u64 {
        Session[epoch_addr].grace_until_micros
    }

    public fun ready_nodes(epoch_addr: address): vector<bool> {
        Session[epoch_addr].ready_nodes
    }

    fun assert_controller(controller: &signer, session: &Session) {
        assert!(controller.address_of() == session.controller, error::permission_denied(E_ONLY_CONTROLLER));
    }

    fun validate_committee(nodes: &vector<address>, threshold: u64) {
        let n = nodes.length();
        assert!(threshold >= 2 && 2 * threshold > n && threshold <= n, error::invalid_argument(E_INVALID_COMMITTEE));
        let seen: vector<address> = vector[];
        nodes.for_each_ref(|node| {
            assert!(!seen.contains(node), error::invalid_argument(E_INVALID_COMMITTEE));
            seen.push_back(*node);
        });
    }
}

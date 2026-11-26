module ace::network {
    use aptos_framework::multisig_account;
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_framework::timestamp;
    use aptos_framework::transaction_context;
    use aptos_std::bcs_stream;
    use std::bcs;
    use std::error;
    use std::option::{Self, Option};
    use std::string::{Self, String};
    use ace::dkg;
    use ace::dkr;
    use ace::epoch;
    use ace::epoch_change;
    use ace::group;
    use ace::pke;
    use ace::publisher::{Self, HandoffCap};
    use ace::secret_usage;
    use ace::worker_config;

    const MIN_RESHARING_INTERVAL_SECS: u64 = 30;
    const MAX_DESCRIPTION_BYTES: u64 = 1024;
    const E_ONLY_GOVERNANCE_ACCOUNT: u64 = 1;
    const E_INVALID_NODE: u64 = 2;
    const E_EPOCH_CHANGE_ALREADY_IN_PROGRESS: u64 = 3;
    const E_INVALID_SECRET_SHARING_PARAMETERS: u64 = 14;
    const E_CAN_ONLY_RETAIN_ACTIVE_SECRET: u64 = 16;
    const E_INVALID_RESHARING_INTERVAL: u64 = 17;
    const E_PROPOSAL_IS_NOT_CURRENT: u64 = 18;
    const E_DESCRIPTION_TOO_LONG: u64 = 20;
    const E_PROPOSAL_DESERIALIZATION_FAILED: u64 = 21;
    const E_NOT_INITIALIZED: u64 = 22;
    const E_ALREADY_INITIALIZED: u64 = 23;
    const E_GRACE_IN_PROGRESS: u64 = 24;
    const E_ADMIN_COMMITTEE_MISMATCH: u64 = 25;
    const E_INVALID_FEATURE: u64 = 26;

    /// Exactly one inbound transition may initialize a successor at a time.
    /// A prior epoch may remain in GRACE beside the current SERVING epoch.
    struct State has key {
        active_epoch: Option<address>,
        initializing_epoch: Option<address>,
        grace_epoch: Option<address>,
        transition: Option<address>,
    }

    /// The publisher cap is handed to network when this module is first published.
    /// It lets the active epoch's multisig publish no-op package upgrades at @ace.
    struct Authority has key {
        handoff_cap: HandoffCap,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    struct ProposedEpochConfig has store, drop, copy {
        nodes: vector<address>,
        threshold: u64,
        epoch_duration_micros: u64,
        secrets_to_retain: vector<address>,
        new_secrets: vector<secret_usage::SecretRequest>,
        description: String,
        target_epoch: u64,
        next_admin_multisig: address,
        /// Numeric feature IDs in [0, 63], unioned with the active epoch's set.
        features_to_activate: vector<u64>,
    }

    struct SecretInfo has drop {
        current_session: address,
        keypair_id: address,
        scheme: u8,
        expected_usage: u64,
        note: String,
    }

    /// Preserved V0 shape: the active epoch (or E0 INIT before first activation).
    struct StateViewV0 has drop {
        epoch: u64,
        epoch_start_time_micros: u64,
        epoch_duration_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<SecretInfo>,
        proposals: vector<Option<ProposalView>>,
        epoch_change_info: Option<EpochChangeView>,
    }

    /// Legacy proposal view remains in V0 wire format; native multisig proposals
    /// are not stored in ACE and this vector is always empty in v6.
    struct ProposalView has drop {
        proposal: ProposedEpochConfig,
        voting_session: address,
        votes: vector<bool>,
        voting_passed: bool,
    }

    struct EpochChangeView has drop {
        triggering_proposal_idx: Option<u64>,
        session_addr: address,
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
    }

    /// Versioned orchestration view. Each epoch blob is BCS(epoch::Session),
    /// including its stage, feature set, secret refs, and inbound/outbound link.
    struct StateViewV1 has drop {
        active_epoch_addr: Option<address>,
        initializing_epoch_addr: Option<address>,
        grace_epoch_addr: Option<address>,
        transition_addr: Option<address>,
        active_epoch_bcs: Option<vector<u8>>,
        initializing_epoch_bcs: Option<vector<u8>>,
        grace_epoch_bcs: Option<vector<u8>>,
    }

    struct NodeDiscoveryV0 has drop {
        addr: address,
        endpoint: Option<String>,
        enc_key: pke::EncryptionKey,
    }

    struct SessionDiscoveryV0 has drop {
        addr: address,
        base_point: group::Element,
        result_pk: group::Element,
        share_pks: vector<group::Element>,
    }

    struct DiscoveryViewV0 has drop {
        state_view: StateViewV0,
        nodes: vector<NodeDiscoveryV0>,
        sessions: vector<SessionDiscoveryV0>,
    }

    /// The current serving epoch and, while its deadline is live, the preceding
    /// grace epoch. Each descriptor is internally consistent at one chain view.
    struct DiscoveryViewV1 has drop {
        serving: DiscoveryViewV0,
        serving_features: u64,
        serving_ready_nodes: vector<bool>,
        grace: Option<DiscoveryViewV0>,
        grace_features: Option<u64>,
        grace_ready_nodes: Option<vector<bool>>,
        grace_until_micros: Option<u64>,
    }

    /// Package publish order is publisher -> epoch_change/epoch -> network.
    fun init_module(ace_signer: &signer) {
        move_to(ace_signer, Authority {
            handoff_cap: publisher::take_handoff_cap(ace_signer),
        });
    }

    #[view]
    public fun state_bcs(): vector<u8> {
        bcs::to_bytes(&State[@ace])
    }

    #[view]
    public fun state_view_v0_bcs(): vector<u8> {
        bcs::to_bytes(&build_state_view_v0())
    }

    #[view]
    public fun state_view_v1_bcs(): vector<u8> {
        let state = &State[@ace];
        let active_epoch_bcs = if (state.active_epoch.is_some()) {
            option::some(epoch::get_session_bcs(*state.active_epoch.borrow()))
        } else { option::none() };
        let initializing_epoch_bcs = if (state.initializing_epoch.is_some()) {
            option::some(epoch::get_session_bcs(*state.initializing_epoch.borrow()))
        } else { option::none() };
        let grace_epoch_bcs = if (state.grace_epoch.is_some()) {
            option::some(epoch::get_session_bcs(*state.grace_epoch.borrow()))
        } else { option::none() };
        bcs::to_bytes(&StateViewV1 {
            active_epoch_addr: state.active_epoch,
            initializing_epoch_addr: state.initializing_epoch,
            grace_epoch_addr: state.grace_epoch,
            transition_addr: state.transition,
            active_epoch_bcs,
            initializing_epoch_bcs,
            grace_epoch_bcs,
        })
    }

    fun view_epoch_addr(state: &State): address {
        if (state.active_epoch.is_some()) {
            *state.active_epoch.borrow()
        } else {
            assert!(state.initializing_epoch.is_some(), error::invalid_state(E_NOT_INITIALIZED));
            *state.initializing_epoch.borrow()
        }
    }

    fun build_state_view_v0(): StateViewV0 {
        let state = &State[@ace];
        let epoch_addr = view_epoch_addr(state);
        let (nodes, threshold, secret_addrs) = epoch::nodes_threshold_secrets(epoch_addr);
        let secrets = secret_infos(&secret_addrs);
        let epoch_change_info = if (state.transition.is_some()) {
            let session_addr = *state.transition.borrow();
            let (nxt_nodes, nxt_threshold) = epoch_change::nxt_nodes_and_threshold(session_addr);
            option::some(EpochChangeView {
                triggering_proposal_idx: option::none(),
                session_addr,
                nxt_nodes,
                nxt_threshold,
            })
        } else { option::none() };
        StateViewV0 {
            epoch: epoch::epoch(epoch_addr),
            epoch_start_time_micros: epoch::serving_since_micros(epoch_addr),
            epoch_duration_micros: epoch::epoch_duration_micros(epoch_addr),
            cur_nodes: nodes,
            cur_threshold: threshold,
            secrets,
            proposals: vector[],
            epoch_change_info,
        }
    }

    fun secret_infos(secret_addrs: &vector<address>): vector<SecretInfo> {
        let result = vector[];
        secret_addrs.for_each_ref(|secret_ref| {
            let addr = *secret_ref;
            let (keypair_id, scheme, expected_usage, note) = if (dkg::is_session(addr)) {
                dkg::keypair_id_scheme_usage_and_note(addr)
            } else {
                dkr::keypair_id_scheme_usage_and_note(addr)
            };
            result.push_back(SecretInfo { current_session: addr, keypair_id, scheme, expected_usage, note });
        });
        result
    }

    // Kept for clients that only need the current serving epoch.
    #[view]
    public fun discovery_view_v0_bcs(): vector<u8> {
        let state = &State[@ace];
        let epoch_addr = view_epoch_addr(state);
        bcs::to_bytes(&build_discovery_view_v0(epoch_addr, build_state_view_v0()))
    }

    #[view]
    public fun discovery_view_v1_bcs(): vector<u8> {
        let serving_state_view = build_state_view_v0();
        let state = &State[@ace];
        let serving_addr = view_epoch_addr(state);
        let serving = build_discovery_view_v0(serving_addr, serving_state_view);
        let grace_addr = if (state.grace_epoch.is_some()
            && !epoch::grace_expired(*state.grace_epoch.borrow())) {
            state.grace_epoch
        } else { option::none() };
        let (grace, grace_features, grace_ready_nodes, grace_until_micros) = if (grace_addr.is_some()) {
            let addr = *grace_addr.borrow();
            (
                option::some(build_discovery_view_v0(addr, build_epoch_state_view_v0(addr))),
                option::some(epoch::features(addr)),
                option::some(epoch::ready_nodes(addr)),
                option::some(epoch::grace_until_micros(addr)),
            )
        } else { (option::none(), option::none(), option::none(), option::none()) };
        bcs::to_bytes(&DiscoveryViewV1 {
            serving,
            serving_features: epoch::features(serving_addr),
            serving_ready_nodes: epoch::ready_nodes(serving_addr),
            grace,
            grace_features,
            grace_ready_nodes,
            grace_until_micros,
        })
    }

    fun build_epoch_state_view_v0(epoch_addr: address): StateViewV0 {
        let (nodes, threshold, secret_addrs) = epoch::nodes_threshold_secrets(epoch_addr);
        StateViewV0 {
            epoch: epoch::epoch(epoch_addr),
            epoch_start_time_micros: epoch::serving_since_micros(epoch_addr),
            epoch_duration_micros: epoch::epoch_duration_micros(epoch_addr),
            cur_nodes: nodes,
            cur_threshold: threshold,
            secrets: secret_infos(&secret_addrs),
            proposals: vector[],
            epoch_change_info: option::none(),
        }
    }

    fun build_discovery_view_v0(epoch_addr: address, state_view: StateViewV0): DiscoveryViewV0 {
        let (node_addrs, _, secret_addrs) = epoch::nodes_threshold_secrets(epoch_addr);
        let nodes = vector[];
        node_addrs.for_each_ref(|node_ref| {
            let node = *node_ref;
            let endpoint = if (worker_config::has_endpoint(node)) {
                option::some(worker_config::get_endpoint(node))
            } else { option::none() };
            nodes.push_back(NodeDiscoveryV0 {
                addr: node,
                endpoint,
                enc_key: worker_config::get_pke_enc_key(node),
            });
        });
        let session_addrs = vector[];
        secret_addrs.for_each_ref(|secret_ref| {
            let addr = *secret_ref;
            let (keypair_id, _, _, _) = if (dkg::is_session(addr)) {
                dkg::keypair_id_scheme_usage_and_note(addr)
            } else {
                dkr::keypair_id_scheme_usage_and_note(addr)
            };
            if (!session_addrs.contains(&addr)) session_addrs.push_back(addr);
            if (!session_addrs.contains(&keypair_id)) session_addrs.push_back(keypair_id);
        });
        let sessions = vector[];
        session_addrs.for_each(|addr| {
            let (base_point, result_pk, share_pks) = if (dkg::is_session(addr)) {
                dkg::base_result_shares(addr)
            } else {
                dkr::base_result_shares(addr)
            };
            sessions.push_back(SessionDiscoveryV0 { addr, base_point, result_pk, share_pks });
        });
        DiscoveryViewV0 {
            state_view,
            nodes,
            sessions,
        }
    }

    // The initial multisig starts E0 INIT. Its first package publication made
    // @ace a resource account; network holds the one-shot publisher handoff cap.
    #[randomness]
    entry fun start_initial_epoch(
        governance: &signer,
        nodes: vector<address>,
        threshold: u64,
        resharing_interval_secs: u64,
        initial_secret_requests_bcs: vector<u8>,
        initial_features: vector<u64>,
    ) {
        assert!(governance.address_of() == publisher::initial_multisig(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        assert!(transaction_context::is_multisig_payload_txn(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        assert!(!exists<State>(@ace), error::invalid_state(E_ALREADY_INITIALIZED));
        validate_committee(&nodes, threshold);
        assert_multisig_matches(governance.address_of(), &nodes, threshold);
        assert!(resharing_interval_secs >= MIN_RESHARING_INTERVAL_SECS, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));
        nodes.for_each_ref(|node| {
            assert!(worker_config::has_pke_enc_key(*node), error::invalid_argument(E_INVALID_NODE));
        });
        let initial_secrets = parse_secret_requests(initial_secret_requests_bcs);
        let features = add_features(0, &initial_features);
        let ace_signer = publisher::ace_signer(&Authority[@ace].handoff_cap);
        let object_ref = object::create_sticky_object(@ace);
        move_to(&ace_signer, SignerStore { extend_ref: object_ref.generate_extend_ref() });
        let controller = object_ref.generate_signer();
        let duration_micros = resharing_interval_secs * 1_000_000;
        let transition = epoch_change::new_session(
            &controller, vector[], 0, nodes, threshold,
            duration_micros, features, vector[], initial_secrets,
        );
        let initial_epoch = epoch::new_session(
            &controller, 0, nodes, threshold, governance.address_of(),
            duration_micros, features, transition,
        );
        move_to(&ace_signer, State {
            active_epoch: option::none(),
            initializing_epoch: option::some(initial_epoch),
            grace_epoch: option::none(),
            transition: option::some(transition),
        });
    }

    // Advance a shared transition or retire the preceding epoch's 60s grace.
    // This is permissionless progress, never a new governance decision.
    #[randomness]
    entry fun touch() {
        let state = &mut State[@ace];
        if (state.grace_epoch.is_some()) {
            let old_addr = *state.grace_epoch.borrow();
            if (epoch::grace_expired(old_addr)) {
                let controller = (&SignerStore[@ace]).extend_ref.generate_signer_for_extending();
                epoch::finish_grace(&controller, old_addr);
                state.grace_epoch = option::none();
            };
            return;
        };
        if (state.initializing_epoch.is_some()) {
            let next_addr = *state.initializing_epoch.borrow();
            if (epoch::ready_to_serve(next_addr)) {
                let (next_nodes, next_threshold, _) = epoch::nodes_threshold_secrets(next_addr);
                assert_multisig_matches(epoch::admin_multisig(next_addr), &next_nodes, next_threshold);
                let controller = (&SignerStore[@ace]).extend_ref.generate_signer_for_extending();
                epoch::begin_serving(&controller, next_addr);
                if (state.active_epoch.is_some()) {
                    let old_addr = *state.active_epoch.borrow();
                    epoch::begin_grace(&controller, old_addr);
                    state.grace_epoch = option::some(old_addr);
                };
                state.active_epoch = option::some(next_addr);
                state.initializing_epoch = option::none();
                state.transition = option::none();
            };
            return;
        };
        if (state.active_epoch.is_some()) {
            let active_addr = *state.active_epoch.borrow();
            let now_micros = timestamp::now_microseconds();
            if (now_micros - epoch::serving_since_micros(active_addr) >= epoch::epoch_duration_micros(active_addr)) {
                let (nodes, threshold, secrets) = epoch::nodes_threshold_secrets(active_addr);
                let admin_multisig = epoch::admin_multisig(active_addr);
                assert_multisig_matches(admin_multisig, &nodes, threshold);
                let proposal = ProposedEpochConfig {
                    nodes,
                    threshold,
                    epoch_duration_micros: epoch::epoch_duration_micros(active_addr),
                    secrets_to_retain: secrets,
                    new_secrets: vector[],
                    description: string::utf8(b"automatic resharing"),
                    target_epoch: epoch::epoch(active_addr),
                    next_admin_multisig: admin_multisig,
                    features_to_activate: vector[],
                };
                begin_transition(state, active_addr, proposal);
            }
        }
    }

    // Current epoch's native multisig decides a single E -> E+1 handoff.
    #[randomness]
    entry fun execute_epoch_config(governance: &signer, proposal_bcs: vector<u8>) {
        assert!(transaction_context::is_multisig_payload_txn(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let state = &mut State[@ace];
        assert!(state.active_epoch.is_some(), error::invalid_state(E_NOT_INITIALIZED));
        assert!(state.initializing_epoch.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        assert!(state.grace_epoch.is_none(), error::invalid_state(E_GRACE_IN_PROGRESS));
        let active_addr = *state.active_epoch.borrow();
        let admin_multisig = epoch::admin_multisig(active_addr);
        assert!(governance.address_of() == admin_multisig, error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let (nodes, threshold, _) = epoch::nodes_threshold_secrets(active_addr);
        assert_multisig_matches(admin_multisig, &nodes, threshold);
        let proposal = proposal_from_bcs(proposal_bcs);
        validate_proposal(active_addr, &proposal);
        begin_transition(state, active_addr, proposal);
    }

    /// A package upgrade is authorized by the currently serving epoch's admin
    /// multisig. The package itself must remain behaviorally inert until its
    /// corresponding feature IDs are activated in a later epoch proposal.
    public entry fun publish_upgrade(
        governance: &signer,
        metadata_serialized: vector<u8>,
        modules: vector<vector<u8>>,
    ) {
        assert!(transaction_context::is_multisig_payload_txn(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let state = &State[@ace];
        assert!(state.active_epoch.is_some(), error::invalid_state(E_NOT_INITIALIZED));
        assert!(state.initializing_epoch.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        assert!(state.grace_epoch.is_none(), error::invalid_state(E_GRACE_IN_PROGRESS));
        let active_addr = *state.active_epoch.borrow();
        let admin_multisig = epoch::admin_multisig(active_addr);
        assert!(governance.address_of() == admin_multisig, error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let (nodes, threshold, _) = epoch::nodes_threshold_secrets(active_addr);
        assert_multisig_matches(admin_multisig, &nodes, threshold);
        publisher::publish_with_cap(&Authority[@ace].handoff_cap, metadata_serialized, modules);
    }

    fun begin_transition(state: &mut State, active_addr: address, proposal: ProposedEpochConfig) {
        assert!(state.initializing_epoch.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        assert!(state.grace_epoch.is_none(), error::invalid_state(E_GRACE_IN_PROGRESS));
        let (cur_nodes, cur_threshold, _) = epoch::nodes_threshold_secrets(active_addr);
        let next_features = add_features(epoch::features(active_addr), &proposal.features_to_activate);
        let controller = (&SignerStore[@ace]).extend_ref.generate_signer_for_extending();
        let transition = epoch_change::new_session(
            &controller, cur_nodes, cur_threshold,
            proposal.nodes, proposal.threshold, proposal.epoch_duration_micros, next_features,
            proposal.secrets_to_retain, proposal.new_secrets,
        );
        let next_addr = epoch::new_session(
            &controller, epoch::epoch(active_addr) + 1,
            proposal.nodes, proposal.threshold, proposal.next_admin_multisig,
            proposal.epoch_duration_micros, next_features, transition,
        );
        epoch::begin_handoff(&controller, active_addr, transition);
        state.initializing_epoch = option::some(next_addr);
        state.transition = option::some(transition);
    }

    fun proposal_from_bcs(proposal_bcs: vector<u8>): ProposedEpochConfig {
        let stream = bcs_stream::new(proposal_bcs);
        let proposal = ProposedEpochConfig {
            nodes: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_address(stream)),
            threshold: bcs_stream::deserialize_u64(&mut stream),
            epoch_duration_micros: bcs_stream::deserialize_u64(&mut stream),
            secrets_to_retain: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_address(stream)),
            new_secrets: bcs_stream::deserialize_vector(&mut stream, |stream| {
                secret_usage::new_request(
                    bcs_stream::deserialize_u64(stream),
                    bcs_stream::deserialize_string(stream),
                )
            }),
            description: bcs_stream::deserialize_string(&mut stream),
            target_epoch: bcs_stream::deserialize_u64(&mut stream),
            next_admin_multisig: bcs_stream::deserialize_address(&mut stream),
            features_to_activate: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_u64(stream)),
        };
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_PROPOSAL_DESERIALIZATION_FAILED));
        proposal
    }

    fun parse_secret_requests(payload_bcs: vector<u8>): vector<secret_usage::SecretRequest> {
        let stream = bcs_stream::new(payload_bcs);
        let requests = bcs_stream::deserialize_vector(&mut stream, |stream| {
            secret_usage::new_request(
                bcs_stream::deserialize_u64(stream),
                bcs_stream::deserialize_string(stream),
            )
        });
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_PROPOSAL_DESERIALIZATION_FAILED));
        requests.for_each_ref(|request| { secret_usage::validate_request(request); });
        requests
    }

    fun validate_proposal(active_addr: address, proposal: &ProposedEpochConfig) {
        assert!(proposal.target_epoch == epoch::epoch(active_addr), error::invalid_argument(E_PROPOSAL_IS_NOT_CURRENT));
        assert!(string::length(&proposal.description) <= MAX_DESCRIPTION_BYTES, error::invalid_argument(E_DESCRIPTION_TOO_LONG));
        validate_committee(&proposal.nodes, proposal.threshold);
        assert_multisig_matches(proposal.next_admin_multisig, &proposal.nodes, proposal.threshold);
        assert!(proposal.epoch_duration_micros >= MIN_RESHARING_INTERVAL_SECS * 1_000_000, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));
        proposal.nodes.for_each_ref(|node| {
            assert!(worker_config::has_pke_enc_key(*node), error::invalid_argument(E_INVALID_NODE));
        });
        proposal.new_secrets.for_each_ref(|request| { secret_usage::validate_request(request); });
        let (_, _, active_secrets) = epoch::nodes_threshold_secrets(active_addr);
        let retained: vector<address> = vector[];
        proposal.secrets_to_retain.for_each_ref(|secret_addr| {
            assert!(active_secrets.contains(secret_addr), error::invalid_argument(E_CAN_ONLY_RETAIN_ACTIVE_SECRET));
            assert!(!retained.contains(secret_addr), error::invalid_argument(E_CAN_ONLY_RETAIN_ACTIVE_SECRET));
            retained.push_back(*secret_addr);
        });
        add_features(epoch::features(active_addr), &proposal.features_to_activate);
    }

    fun validate_committee(nodes: &vector<address>, threshold: u64) {
        let n = nodes.length();
        assert!(threshold >= 2 && 2 * threshold > n && threshold <= n, error::invalid_argument(E_INVALID_SECRET_SHARING_PARAMETERS));
        let seen: vector<address> = vector[];
        nodes.for_each_ref(|node| {
            assert!(!seen.contains(node), error::invalid_argument(E_INVALID_NODE));
            seen.push_back(*node);
        });
    }

    fun assert_multisig_matches(multisig: address, nodes: &vector<address>, threshold: u64) {
        assert!(multisig_account::num_signatures_required(multisig) == threshold, error::invalid_state(E_ADMIN_COMMITTEE_MISMATCH));
        let owners = multisig_account::owners(multisig);
        assert!(owners.length() == nodes.length(), error::invalid_state(E_ADMIN_COMMITTEE_MISMATCH));
        owners.for_each_ref(|owner| {
            assert!(nodes.contains(owner), error::invalid_state(E_ADMIN_COMMITTEE_MISMATCH));
        });
    }

    fun add_features(current: u64, feature_ids: &vector<u64>): u64 {
        let features = current;
        feature_ids.for_each_ref(|feature_id| {
            assert!(*feature_id < 64, error::invalid_argument(E_INVALID_FEATURE));
            features = features | (1u64 << (*feature_id as u8));
        });
        features
    }
}

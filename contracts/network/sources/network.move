module ace::network {
    use std::error;
    use ace::worker_config;
    use ace::group;
    use ace::pke;
    use aptos_framework::timestamp;
    use ace::dkr;
    use std::option::{Option, Self};
    use ace::dkg;
    use ace::secret_usage;
    use ace::epoch_change;
    use std::bcs;
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_std::bcs_stream;
    use std::vector::range;
    use ace::voting;
    use std::string::{Self, String};

    const MIN_RESHARING_INTERVAL_SECS: u64 = 30;
    const MAX_DESCRIPTION_BYTES: u64 = 1024;

    const E_ONLY_GOVERNANCE_ACCOUNT: u64 = 1;
    const E_INVALID_NODE: u64 = 2;
    const E_EPOCH_CHANGE_ALREADY_IN_PROGRESS: u64 = 3;
    const E_ONLY_ADMIN_OR_CURRENT_NODE_CAN_PROPOSE: u64 = 6;
    const E_UNREACHABLE: u64 = 7;
    const E_PROPOSAL_ALREADY_EXECUTED: u64 = 8;
    const E_ONLY_CURRENT_NODE_CAN_PROPOSE: u64 = 9;
    const E_PROPOSAL_NOT_PENDING: u64 = 10;
    const E_ALREADY_VOTED: u64 = 11;
    const E_UNSUPPORTED_PROPOSAL_SCHEME: u64 = 12;
    const E_PROPOSAL_DESERIALIZATION_FAILED: u64 = 13;
    const E_INVALID_SECRET_SHARING_PARAMETERS: u64 = 14;
    const E_UNSUPPORTED_SECRET_SCHEME: u64 = 15;
    const E_CAN_ONLY_RETAIN_ACTIVE_SECRET: u64 = 16;
    const E_INVALID_RESHARING_INTERVAL: u64 = 17;
    const E_PROPOSAL_IS_NOT_CURRENT: u64 = 18;
    const E_YOU_ALREADY_PROPOSED_IN_THIS_EPOCH: u64 = 19;
    const E_DESCRIPTION_TOO_LONG: u64 = 20;

    struct ProposalState has store, drop {
        proposal: ProposedEpochConfig,
        voting_session: address,
    }

    struct EpochChangeInfo has store, drop {
        triggering_proposal_idx: Option<u64>,
        session_addr: address,
    }

    struct State has key {
        epoch: u64,
        epoch_start_time_micros: u64,
        epoch_duration_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<address>,
        /// Stores proposals from nodes and admin, therefore having length n+1. indices 0..<n are for nodes, n is for admin.
        proposals: vector<Option<ProposalState>>,
        epoch_change_info: Option<EpochChangeInfo>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    struct ProposedEpochConfig has store, drop, copy {
        nodes: vector<address>,
        threshold: u64,
        epoch_duration_micros: u64,
        /// can only be a subset of the currently active secret set.
        secrets_to_retain: vector<address>,
        /// Each results in a DKG in epoch change.
        new_secrets: vector<secret_usage::SecretRequest>,
        /// limit: 1024 bytes
        description: String,
        /// Must match state.epoch at submission time; prevents stale proposals from firing.
        target_epoch: u64,
    }

    struct SecretInfo has drop {
        current_session: address,
        keypair_id: address,
        scheme: u8,
        expected_usage: u64,
        note: String,
    }

    #[view]
    public fun state_bcs(): vector<u8> {
        bcs::to_bytes(&State[@ace])
    }

    struct ProposalView has drop {
        proposal: ProposedEpochConfig,
        voting_session: address,
        /// votes[i] == true iff cur_nodes[i] has voted for this proposal.
        votes: vector<bool>,
        /// true iff enough votes have been cast to pass (i.e. touch would mark it PASSED).
        voting_passed: bool,
    }

    struct EpochChangeView has drop {
        triggering_proposal_idx: Option<u64>,
        session_addr: address,
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
    }

    struct StateViewV0 has drop {
        epoch: u64,
        epoch_start_time_micros: u64,
        epoch_duration_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<SecretInfo>,
        /// Length == cur_nodes.length() + 1; index i is node i's proposal, last index is admin's.
        proposals: vector<Option<ProposalView>>,
        epoch_change_info: Option<EpochChangeView>,
    }

    // Single BCS-encoded snapshot covering network::State plus all sub-protocol data nodes
    // need to make local decisions (touch, epoch-change-nxt membership, proposal vote status).
    #[view]
    public fun state_view_v0_bcs(): vector<u8> {
        bcs::to_bytes(&build_state_view_v0())
    }

    fun build_state_view_v0(): StateViewV0 {
        let state = &State[@ace];

        let proposals = vector[];
        let i = 0;
        while (i < state.proposals.length()) {
            let p = &state.proposals[i];
            if (p.is_none()) {
                proposals.push_back(option::none());
            } else {
                let ps = p.borrow();
                let (votes, threshold) = voting::session_votes_and_threshold(ps.voting_session);
                let num_votes = 0u64;
                let j = 0;
                while (j < votes.length()) {
                    if (votes[j]) { num_votes += 1; };
                    j += 1;
                };
                proposals.push_back(option::some(ProposalView {
                    proposal: ps.proposal,
                    voting_session: ps.voting_session,
                    votes,
                    voting_passed: num_votes >= threshold,
                }));
            };
            i += 1;
        };

        let epoch_change_info = if (state.epoch_change_info.is_some()) {
            let info = state.epoch_change_info.borrow();
            let (nxt_nodes, nxt_threshold) = epoch_change::nxt_nodes_and_threshold(info.session_addr);
            option::some(EpochChangeView {
                triggering_proposal_idx: info.triggering_proposal_idx,
                session_addr: info.session_addr,
                nxt_nodes,
                nxt_threshold,
            })
        } else {
            option::none()
        };

        let secrets = {
            let n = state.secrets.length();
            let i = 0;
            let result = vector[];
            while (i < n) {
                let addr = state.secrets[i];
                let (keypair_id, scheme, expected_usage, note) = if (dkg::is_session(addr)) {
                    dkg::keypair_id_scheme_usage_and_note(addr)
                } else {
                    dkr::keypair_id_scheme_usage_and_note(addr)
                };
                result.push_back(SecretInfo { current_session: addr, keypair_id, scheme, expected_usage, note });
                i += 1;
            };
            result
        };

        StateViewV0 {
            epoch: state.epoch,
            epoch_start_time_micros: state.epoch_start_time_micros,
            epoch_duration_micros: state.epoch_duration_micros,
            cur_nodes: state.cur_nodes,
            cur_threshold: state.cur_threshold,
            secrets,
            proposals,
            epoch_change_info,
        }
    }

    struct NodeDiscoveryV0 has drop {
        addr: address,
        /// worker_config::get_endpoint(addr); none if the node has not registered one yet.
        endpoint: Option<String>,
        enc_key: pke::EncryptionKey,
    }

    /// A secret's session, reduced to exactly what an off-chain client reads: the base point, the
    /// master public key (result_pk), and the per-holder share PKs. Uniform across DKG and DKR
    /// sessions, so no dkg/dkr discriminator is needed.
    struct SessionDiscoveryV0 has drop {
        addr: address,
        base_point: group::Element,
        result_pk: group::Element,
        share_pks: vector<group::Element>,
    }

    /// Everything an off-chain client needs to encrypt / decrypt / VRF-derive without any
    /// follow-up node-API calls, bundled into one typed #[view].
    struct DiscoveryViewV0 has drop {
        state_view: StateViewV0,
        /// One per State.cur_nodes, in cur_nodes order.
        nodes: vector<NodeDiscoveryV0>,
        /// Dedup union over secrets of {current_session, keypair_id}. keypair_id is always a DKG
        /// session (the origin); current_session is dkg for initial secrets, dkr after resharing.
        sessions: vector<SessionDiscoveryV0>,
    }

    // Single #[view] that collapses the per-decryption 2N+1 node-API calls into one, so a keyless
    // discovery service can serve the whole snapshot. See DiscoveryViewV0.
    #[view]
    public fun discovery_view_v0_bcs(): vector<u8> {
        let state = &State[@ace];

        let nodes = vector[];
        state.cur_nodes.for_each_ref(|node_ref| {
            let node = *node_ref;
            let endpoint = if (worker_config::has_endpoint(node)) {
                option::some(worker_config::get_endpoint(node))
            } else {
                option::none()
            };
            nodes.push_back(NodeDiscoveryV0 {
                addr: node,
                endpoint,
                enc_key: worker_config::get_pke_enc_key(node),
            });
        });

        // Collect the dedup union of {current_session, keypair_id} over all secrets.
        let session_addrs = vector[];
        state.secrets.for_each_ref(|secret_ref| {
            let current_session = *secret_ref;
            let (keypair_id, _, _, _) = if (dkg::is_session(current_session)) {
                dkg::keypair_id_scheme_usage_and_note(current_session)
            } else {
                dkr::keypair_id_scheme_usage_and_note(current_session)
            };
            if (!session_addrs.contains(&current_session)) {
                session_addrs.push_back(current_session);
            };
            if (!session_addrs.contains(&keypair_id)) {
                session_addrs.push_back(keypair_id);
            };
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

        bcs::to_bytes(&DiscoveryViewV0 {
            state_view: build_state_view_v0(),
            nodes,
            sessions,
        })
    }

    entry fun start_initial_epoch(ace: &signer, nodes: vector<address>, threshold: u64, resharing_interval_secs: u64) {
        assert!(@ace == ace.address_of(), error::invalid_argument(E_ONLY_GOVERNANCE_ACCOUNT));
        assert!(aptos_framework::transaction_context::is_multisig_payload_txn(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let n = nodes.length();
        validate_committee(&nodes, threshold);
        assert!(resharing_interval_secs >= MIN_RESHARING_INTERVAL_SECS, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));
        nodes.for_each(|node| {
            assert!(worker_config::has_pke_enc_key(node), error::invalid_argument(E_INVALID_NODE));
        });

        let object_ref = object::create_sticky_object(@ace);
        let extend_ref = object_ref.generate_extend_ref();
        move_to(ace, SignerStore {
            extend_ref,
        });

        let epoch_start_time_micros = timestamp::now_microseconds();
        move_to(ace, State {
            epoch: 0,
            epoch_start_time_micros,
            epoch_duration_micros: resharing_interval_secs * 1_000_000,
            cur_nodes: nodes,
            cur_threshold: threshold,
            secrets: vector[],
            proposals: range(0, n+1).map(|_| option::none()),
            epoch_change_info: option::none(),
        });
    }

    fun original_dkg_session(secret_addr: address): address {
        if (dkg::completed(secret_addr)) {
            secret_addr
        } else {
            let (original_dkg_session, _, _, _, _, _) = dkr::params_for_resharing(secret_addr);
            original_dkg_session
        }
    }

    #[randomness]
    /// Node should call this only after the current epoch is older than the epoch duration.
    entry fun touch() {
        let state = &mut State[@ace];
        let now_micros = timestamp::now_microseconds();
        if (state.epoch_change_info.is_some()) {
            let session = state.epoch_change_info.borrow().session_addr;
            if (epoch_change::completed(session)) {
                let (nodes, threshold, secrets, epoch_duration_micros) = epoch_change::results(session);
                state.epoch += 1;
                state.epoch_start_time_micros = now_micros;
                state.cur_nodes = nodes;
                state.cur_threshold = threshold;
                state.secrets = secrets;
                state.epoch_duration_micros = epoch_duration_micros;
                state.proposals = range(0, nodes.length()+1).map(|_| option::none());
                state.epoch_change_info = option::none();
            }
        } else {
            if (now_micros - state.epoch_start_time_micros >= state.epoch_duration_micros) {
                let signer_store = &SignerStore[@ace];
                let service_account = signer_store.extend_ref.generate_signer_for_extending();
                let epoch_change_session = epoch_change::new_session(
                    &service_account,
                    state.cur_nodes,
                    state.cur_threshold,
                    state.cur_nodes, // nxt_nodes
                    state.cur_threshold, // nxt_threshold
                    state.epoch_duration_micros, // nxt_epoch_duration_micros
                    state.secrets, // secrets_to_reshare
                    vector[], // new_secret_scheme
                );
                state.epoch_change_info = option::some(EpochChangeInfo {
                    triggering_proposal_idx: option::none(),
                    session_addr: epoch_change_session,
                });
            }
        }
    }

    #[randomness]
    /// Execute an epoch configuration approved by the native multisig at @ace.
    /// Fresh deployment must bind @ace to that multisig's governance signer.
    entry fun execute_epoch_config(governance: &signer, proposal_bcs: vector<u8>) {
        assert!(@ace == governance.address_of(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        assert!(aptos_framework::transaction_context::is_multisig_payload_txn(), error::permission_denied(E_ONLY_GOVERNANCE_ACCOUNT));
        let state = &mut State[@ace];
        assert!(state.epoch_change_info.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        let proposal = proposal_from_bcs(proposal_bcs);
        validate_proposal(state, &proposal);

        let signer_store = &SignerStore[@ace];
        let service_account = signer_store.extend_ref.generate_signer_for_extending();
        let session = epoch_change::new_session(
            &service_account,
            state.cur_nodes,
            state.cur_threshold,
            proposal.nodes,
            proposal.threshold,
            proposal.epoch_duration_micros,
            proposal.secrets_to_retain,
            proposal.new_secrets,
        );
        // Native multisig tracks the proposal; no ACE voting slot is created.
        state.epoch_change_info = option::some(EpochChangeInfo {
            triggering_proposal_idx: option::none(),
            session_addr: session,
        });
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
        };
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_PROPOSAL_DESERIALIZATION_FAILED));
        proposal
    }

    fun validate_proposal(state: &State, proposal: &ProposedEpochConfig) {
        validate_proposal_header(state.epoch, proposal);
        proposal.nodes.for_each_ref(|node| {
            assert!(worker_config::has_pke_enc_key(*node), error::invalid_argument(E_INVALID_NODE));
        });

        // Validate epoch duration.
        assert!(proposal.epoch_duration_micros >= MIN_RESHARING_INTERVAL_SECS * 1_000_000, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));

        // Validate new secrets.
        proposal.new_secrets.for_each_ref(|request| {
            secret_usage::validate_request(request);
        });

        // Validate secrets.
        proposal.secrets_to_retain.for_each_ref(|secret_addr| {
            assert!(state.secrets.contains(secret_addr), error::invalid_argument(E_CAN_ONLY_RETAIN_ACTIVE_SECRET));
        });
    }

    fun validate_proposal_header(current_epoch: u64, proposal: &ProposedEpochConfig) {
        // Validate target epoch before node/resource checks — reject stale proposals.
        assert!(proposal.target_epoch == current_epoch, error::invalid_argument(E_PROPOSAL_IS_NOT_CURRENT));
        assert!(string::length(&proposal.description) <= MAX_DESCRIPTION_BYTES, error::invalid_argument(E_DESCRIPTION_TOO_LONG));
        validate_committee(&proposal.nodes, proposal.threshold);
    }

    fun validate_committee(nodes: &vector<address>, threshold: u64) {
        let n = nodes.length();
        let t = threshold;
        assert!(t >= 2 && 2*t > n && t <= n, error::invalid_argument(E_INVALID_SECRET_SHARING_PARAMETERS));
        let seen: vector<address> = vector[];
        nodes.for_each_ref(|node| {
            assert!(!seen.contains(node), error::invalid_argument(E_INVALID_NODE));
            seen.push_back(*node);
        });
    }

    #[test]
    fun test_committee_accepts_unique_nodes() {
        validate_committee(&vector[@0xc, @0xa, @0xb], 2);
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = Self)]
    fun test_committee_rejects_duplicate_nodes() {
        validate_committee(&vector[@0xa, @0xa], 2);
    }

    #[test]
    #[expected_failure(abort_code = 65538, location = Self)]
    fun test_proposal_header_rejects_nonadjacent_duplicate_nodes() {
        let proposal = proposal_header_fixture();
        proposal.nodes = vector[@0xa, @0xb, @0xa];
        validate_proposal_header(7, &proposal);
    }

    #[test_only]
    fun proposal_header_fixture(): ProposedEpochConfig {
        ProposedEpochConfig {
            nodes: vector[@0xa, @0xb],
            threshold: 2,
            epoch_duration_micros: MIN_RESHARING_INTERVAL_SECS * 1_000_000,
            secrets_to_retain: vector[],
            new_secrets: vector[],
            description: string::utf8(b"configuration test"),
            target_epoch: 7,
        }
    }

    // These test config-header validation, not native multisig approval thresholds.
    #[test]
    fun test_proposal_header_accepts_current_epoch_and_threshold() {
        let proposal = proposal_header_fixture();
        validate_proposal_header(7, &proposal);
    }

    #[test]
    #[expected_failure(abort_code = 65554, location = Self)]
    fun test_proposal_header_rejects_stale_epoch() {
        let proposal = proposal_header_fixture();
        validate_proposal_header(8, &proposal);
    }

    #[test]
    #[expected_failure(abort_code = 65550, location = Self)]
    fun test_proposal_header_rejects_invalid_threshold() {
        let proposal = proposal_header_fixture();
        proposal.threshold = 1;
        validate_proposal_header(7, &proposal);
    }

    #[test]
    #[expected_failure(abort_code = 65556, location = Self)]
    fun test_proposal_header_rejects_long_description() {
        let proposal = proposal_header_fixture();
        proposal.description = string::utf8(range(0, MAX_DESCRIPTION_BYTES + 1).map(|_| 97u8));
        validate_proposal_header(7, &proposal);
    }

    // No State, SignerStore or worker configuration is initialized in these tests.
    // Authorization must reject before payload decoding or resource access.
    // The pinned framework reports a non-multisig context in ordinary unit tests.
    #[test(governance = @ace)]
    #[expected_failure(abort_code = 327681, location = Self)]
    fun test_direct_governance_signer_cannot_execute(governance: signer) {
        execute_epoch_config(&governance, vector[]);
    }

    #[test(other = @0xbad)]
    #[expected_failure(abort_code = 327681, location = Self)]
    fun test_other_signer_cannot_execute(other: signer) {
        execute_epoch_config(&other, vector[]);
    }

    #[test(governance = @ace)]
    #[expected_failure(abort_code = 327681, location = Self)]
    fun test_direct_governance_signer_cannot_bootstrap(governance: signer) {
        start_initial_epoch(&governance, vector[], 0, MIN_RESHARING_INTERVAL_SECS);
    }

    #[test(other = @0xbad)]
    #[expected_failure(abort_code = 65537, location = Self)]
    fun test_other_signer_cannot_bootstrap(other: signer) {
        start_initial_epoch(&other, vector[], 0, MIN_RESHARING_INTERVAL_SECS);
    }
}

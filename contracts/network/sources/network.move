module ace::network {
    use std::error;
    use ace::worker_config;
    use aptos_framework::timestamp;
    use ace::dkr;
    use std::option::{Option, Self};
    use ace::dkg;
    use ace::group;
    use ace::epoch_change;
    use std::bcs;
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_std::bcs_stream;
    use std::vector::range;
    use ace::voting;
    use std::string::String;

    const MIN_RESHARING_INTERVAL_SECS: u64 = 30;

    const E_ONLY_ADMIN_CAN_DO_THIS: u64 = 1;
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
        new_secrets: vector<u8>,
        /// limit: 1024 bytes
        description: String,
        /// Must match state.epoch at submission time; prevents stale proposals from firing.
        target_epoch: u64,
    }

    struct SecretInfo has drop {
        current_session: address,
        keypair_id: address,
        scheme: u8,
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
    // Versioned so new fields can be added in StateViewV1, V2, etc.
    #[view]
    public fun state_view_v0_bcs(): vector<u8> {
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
                let (keypair_id, scheme) = if (dkg::is_session(addr)) {
                    dkg::keypair_id_and_scheme(addr)
                } else {
                    dkr::keypair_id_and_scheme(addr)
                };
                result.push_back(SecretInfo { current_session: addr, keypair_id, scheme });
                i += 1;
            };
            result
        };

        bcs::to_bytes(&StateViewV0 {
            epoch: state.epoch,
            epoch_start_time_micros: state.epoch_start_time_micros,
            epoch_duration_micros: state.epoch_duration_micros,
            cur_nodes: state.cur_nodes,
            cur_threshold: state.cur_threshold,
            secrets,
            proposals,
            epoch_change_info,
        })
    }

    entry fun start_initial_epoch(ace: &signer, nodes: vector<address>, threshold: u64, resharing_interval_secs: u64) {
        assert!(@ace == ace.address_of(), error::invalid_argument(E_ONLY_ADMIN_CAN_DO_THIS));
        let n = nodes.length();
        let t = threshold;
        assert!(t >= 2 && 2*t > n && t <= n, error::invalid_argument(E_INVALID_SECRET_SHARING_PARAMETERS));
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
            // Touch all voting sessions.
            state.proposals.for_each_ref(|proposal: &Option<ProposalState>|{
                if (proposal.is_some()) {
                    let session = proposal.borrow().voting_session;
                    voting::touch(session);
                }
            });

            // Try find an approved proposal.
            let approved_proposal_found = false;
            let approved_proposal_idx = 0;
            let i = 0;
            while (i < state.proposals.length()) {
                let proposal = &state.proposals[i];
                if (proposal.is_some() && voting::completed(proposal.borrow().voting_session)) {
                    approved_proposal_found = true;
                    approved_proposal_idx = i;
                    break;
                };
                i += 1;
            };
            if (approved_proposal_found) {
                let proposed_epoch_config = state.proposals[approved_proposal_idx].borrow().proposal;                 
                // Create a new epoch change session.
                let signer_store = &SignerStore[@ace];
                let service_account = signer_store.extend_ref.generate_signer_for_extending();
                let session = epoch_change::new_session(
                    &service_account,
                    state.cur_nodes,
                    state.cur_threshold,
                    proposed_epoch_config.nodes,
                    proposed_epoch_config.threshold,
                    proposed_epoch_config.epoch_duration_micros,
                    proposed_epoch_config.secrets_to_retain,
                    proposed_epoch_config.new_secrets,
                );
                state.epoch_change_info = option::some(EpochChangeInfo {
                    triggering_proposal_idx: option::some(approved_proposal_idx),
                    session_addr: session,
                });


            } else if (now_micros - state.epoch_start_time_micros >= state.epoch_duration_micros) {
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
    entry fun new_proposal(proposer: &signer, proposal_bcs: vector<u8>) {
        let state = &mut State[@ace];
        let proposer_addr = proposer.address_of();
        let (proposed_by_node, node_idx) = state.cur_nodes.find(|node| *node == proposer_addr);
        assert!(@ace == proposer_addr || proposed_by_node, error::permission_denied(E_ONLY_ADMIN_OR_CURRENT_NODE_CAN_PROPOSE));
        assert!(state.epoch_change_info.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        let proposal = proposal_from_bcs(proposal_bcs);
        validate_proposal(state, &proposal);

        let signer_store = &SignerStore[@ace];
        let service_account = signer_store.extend_ref.generate_signer_for_extending();
        let voting_session = voting::new_session(&service_account, state.cur_nodes, state.cur_threshold);
        let proposal_state = ProposalState {
            proposal,
            voting_session,
        };
        let proposer_idx = if (@ace == proposer_addr) { state.cur_nodes.length() } else { node_idx };
        assert!(state.proposals[proposer_idx].is_none(), error::invalid_state(E_YOU_ALREADY_PROPOSED_IN_THIS_EPOCH));
        state.proposals[proposer_idx] = option::some(proposal_state);

        // Self-approve.
        if (proposed_by_node) {
            voting::vote(proposer, voting_session);
        }
    }

    fun proposal_from_bcs(proposal_bcs: vector<u8>): ProposedEpochConfig {
        let stream = bcs_stream::new(proposal_bcs);
        let proposal = ProposedEpochConfig {
            nodes: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_address(stream)),
            threshold: bcs_stream::deserialize_u64(&mut stream),
            epoch_duration_micros: bcs_stream::deserialize_u64(&mut stream),
            secrets_to_retain: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_address(stream)),
            new_secrets: bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_u8(stream)),
            description: bcs_stream::deserialize_string(&mut stream),
            target_epoch: bcs_stream::deserialize_u64(&mut stream),
        };
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_PROPOSAL_DESERIALIZATION_FAILED));
        proposal
    }

    fun validate_proposal(state: &State, proposal: &ProposedEpochConfig) {
        // Validate target epoch — reject stale proposals.
        assert!(proposal.target_epoch == state.epoch, error::invalid_argument(E_PROPOSAL_IS_NOT_CURRENT));

        // Validate nodes and threshold.
        let n = proposal.nodes.length();
        let t = proposal.threshold;
        assert!(t >= 2 && 2*t > n && t <= n, error::invalid_argument(E_INVALID_SECRET_SHARING_PARAMETERS));
        proposal.nodes.for_each_ref(|node| {
            assert!(worker_config::has_pke_enc_key(*node), error::invalid_argument(E_INVALID_NODE));
        });

        // Validate epoch duration.
        assert!(proposal.epoch_duration_micros >= MIN_RESHARING_INTERVAL_SECS * 1_000_000, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));

        // Validate new secrets.
        proposal.new_secrets.for_each_ref(|scheme| {
            assert!(group::scheme_supported(*scheme), error::invalid_argument(E_UNSUPPORTED_SECRET_SCHEME));
        });

        // Validate secrets.
        proposal.secrets_to_retain.for_each_ref(|secret_addr| {
            assert!(state.secrets.contains(secret_addr), error::invalid_argument(E_CAN_ONLY_RETAIN_ACTIVE_SECRET));
        });
    }
}

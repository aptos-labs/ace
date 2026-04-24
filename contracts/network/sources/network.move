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
    use std::signer::address_of;
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_std::bcs_stream;
    use aptos_framework::event;

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
    const E_NOT_AN_ACTIVE_SECRET: u64 = 16;
    const E_INVALID_RESHARING_INTERVAL: u64 = 17;
    const E_PROPOSAL_IS_NOT_CURRENT: u64 = 18;
    
    struct EpochChangeInfo has copy, drop, store {
        nxt_nodes: vector<address>,
        session: address,
    }

    struct State has key {
        epoch: u64,
        epoch_start_time_micros: u64,
        epoch_duration_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<address>,
        pending_proposals: vector<address>,
        epoch_change_info: Option<EpochChangeInfo>,
    }

    struct SignerStore has key {
        extend_ref: ExtendRef,
    }

    enum Proposal has store {
        CommitteeChange { nodes: vector<address>, threshold: u64 },
        ResharingIntervalUpdate { new_interval_secs: u64 },
        NewSecret { scheme: u8 },
        SecretDeactivation { original_dkg_addr: address },
    }

    struct ProposalState has key {
        epoch: u64,
        proposer: address,
        proposal: Proposal,
        voters: vector<address>,
        executed: bool,

    }

    #[event]
    struct ProposalCreated has drop, store {
        addr: address,
    }

    #[event]
    struct ProposalAccepted has drop, store {
        addr: address,
    }

    #[view]
    public fun state_bcs(): vector<u8> {
        bcs::to_bytes(borrow_global<State>(@ace))
    }

    #[view]
    public fun get_proposal_state_bcs(addr: address): vector<u8> acquires ProposalState {
        bcs::to_bytes(borrow_global<ProposalState>(addr))
    }

    entry fun start_initial_epoch(ace: &signer, nodes: vector<address>, threshold: u64, resharing_interval_secs: u64) {
        assert!(@ace == address_of(ace), error::invalid_argument(E_ONLY_ADMIN_CAN_DO_THIS));
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
            pending_proposals: vector[],
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
        let state = borrow_global_mut<State>(@ace);
        let now_micros = timestamp::now_microseconds();
        if (state.epoch_change_info.is_some()) {
            let EpochChangeInfo { nxt_nodes, session } = *state.epoch_change_info.borrow();
            if (epoch_change::completed(session)) {
                let (nodes, threshold, secrets, epoch_duration_micros) = epoch_change::results(session);
                assert!(nodes == nxt_nodes, error::internal(E_UNREACHABLE));
                state.epoch += 1;
                state.epoch_start_time_micros = now_micros;
                state.cur_nodes = nodes;
                state.cur_threshold = threshold;
                state.secrets = secrets;
                state.epoch_duration_micros = epoch_duration_micros;
                state.epoch_change_info = option::none();
            }
        } else {
            if (now_micros - state.epoch_start_time_micros >= state.epoch_duration_micros) {
                let signer_store = borrow_global<SignerStore>(@ace);
                let caller = signer_store.extend_ref.generate_signer_for_extending();
                let epoch_change_session = epoch_change::new_session(
                    &caller,
                    state.cur_nodes,
                    state.cur_threshold,
                    state.cur_nodes, // nxt_nodes
                    state.cur_threshold, // nxt_threshold
                    state.epoch_duration_micros, // nxt_epoch_duration_micros
                    state.secrets, // secrets_to_reshare
                    option::none(), // new_secret_scheme
                );
                state.epoch_change_info = option::some(EpochChangeInfo {
                    nxt_nodes: state.cur_nodes,
                    session: epoch_change_session,
                });
                state.pending_proposals = vector[];
            }
        }
    }

    #[randomness]
    entry fun new_proposal(proposer: &signer, proposal_bcs: vector<u8>) {
        let state = borrow_global_mut<State>(@ace);
        let proposer_addr = address_of(proposer);
        assert!(@ace == proposer_addr || state.cur_nodes.contains(&proposer_addr), error::permission_denied(E_ONLY_ADMIN_OR_CURRENT_NODE_CAN_PROPOSE));
        assert!(state.epoch_change_info.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        let proposal = proposal_from_bcs(proposal_bcs);
        validate_proposal(state, &proposal);
        let object_ref = object::create_sticky_object(proposer_addr);
        let object_signer = object_ref.generate_signer();
        let object_addr = object_ref.address_from_constructor_ref();
        move_to(&object_signer, ProposalState {
            epoch: state.epoch,
            proposer: proposer_addr,
            proposal,
            voters: vector[], 
            executed: false,
        });
        state.pending_proposals.push_back(object_addr);
        event::emit(ProposalCreated { addr: object_addr });

        // Self-approve.
        approve_proposal(proposer, object_addr);
    }

    #[randomness]
    entry fun approve_proposal(node: &signer, proposal_addr: address) {
        let network_state = borrow_global_mut<State>(@ace);
        let node_addr = address_of(node);
        assert!(network_state.cur_nodes.contains(&node_addr), error::permission_denied(E_ONLY_CURRENT_NODE_CAN_PROPOSE));
        assert!(network_state.pending_proposals.contains(&proposal_addr), error::invalid_argument(E_PROPOSAL_NOT_PENDING));

        let proposal_state = borrow_global_mut<ProposalState>(proposal_addr);
        assert!(proposal_state.epoch == network_state.epoch, error::invalid_argument(E_PROPOSAL_IS_NOT_CURRENT));
        assert!(!proposal_state.executed, error::invalid_argument(E_PROPOSAL_ALREADY_EXECUTED));
        assert!(!proposal_state.voters.contains(&node_addr), error::invalid_argument(E_ALREADY_VOTED));
        proposal_state.voters.push_back(address_of(node));
        maybe_start_epoch_change(network_state, proposal_state);
    }

    fun proposal_from_bcs(proposal_bcs: vector<u8>): Proposal {
        let stream = bcs_stream::new(proposal_bcs);
        let scheme = bcs_stream::deserialize_u8(&mut stream);
        let proposal = if (scheme == 0) {
            let nodes = bcs_stream::deserialize_vector(&mut stream, |stream| bcs_stream::deserialize_address(stream));
            let threshold = bcs_stream::deserialize_u64(&mut stream);
            Proposal::CommitteeChange { nodes, threshold }
        } else if (scheme == 1) {
            let new_interval_secs = bcs_stream::deserialize_u64(&mut stream);
            Proposal::ResharingIntervalUpdate { new_interval_secs }
        } else if (scheme == 2) {
            let scheme = bcs_stream::deserialize_u8(&mut stream);
            Proposal::NewSecret { scheme }
        } else if (scheme == 3) {
            let original_dkg_addr = bcs_stream::deserialize_address(&mut stream);
            Proposal::SecretDeactivation { original_dkg_addr }
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_PROPOSAL_SCHEME)
        };
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_PROPOSAL_DESERIALIZATION_FAILED));
        proposal
    }

    fun validate_proposal(state: &State, proposal: &Proposal) {
        match (proposal) {
            Proposal::CommitteeChange { nodes, threshold } => {
                let n = nodes.length();
                let t = *threshold;
                assert!(t >= 2 && 2*t > n && t <= n, error::invalid_argument(E_INVALID_SECRET_SHARING_PARAMETERS));
                nodes.for_each_ref(|node| {
                    assert!(worker_config::has_pke_enc_key(*node), error::invalid_argument(E_INVALID_NODE));
                });
            }
            Proposal::ResharingIntervalUpdate { new_interval_secs } => {
                assert!(*new_interval_secs >= MIN_RESHARING_INTERVAL_SECS, error::invalid_argument(E_INVALID_RESHARING_INTERVAL));
            }
            Proposal::NewSecret { scheme } => {
                assert!(group::scheme_supported(*scheme), error::invalid_argument(E_UNSUPPORTED_SECRET_SCHEME));
            }
            Proposal::SecretDeactivation { original_dkg_addr } => {
                assert!(state.secrets.any(|secret_addr| original_dkg_session(*secret_addr) == *original_dkg_addr), error::invalid_argument(E_NOT_AN_ACTIVE_SECRET));
            }
        }
    }

    fun maybe_start_epoch_change(network_state: &mut State, proposal_state: &mut ProposalState) {
        if (proposal_state.voters.length() >= network_state.cur_threshold) {
            proposal_state.executed = true;
            let (new_nodes, new_threshold, new_epoch_duration_micros, new_secret_scheme, secrets_to_reshare) = match (&proposal_state.proposal) {
                Proposal::CommitteeChange { nodes, threshold } => {
                    (*nodes, *threshold, network_state.epoch_duration_micros, option::none(), network_state.secrets)
                }
                Proposal::ResharingIntervalUpdate { new_interval_secs } => {
                    (network_state.cur_nodes, network_state.cur_threshold, *new_interval_secs * 1_000_000, option::none(), network_state.secrets)
                }
                Proposal::NewSecret { scheme } => {
                    (network_state.cur_nodes, network_state.cur_threshold, network_state.epoch_duration_micros, option::some(*scheme), network_state.secrets)
                }
                Proposal::SecretDeactivation { original_dkg_addr } => {
                    let secrets_to_reshare = network_state.secrets.filter(|secret_addr| original_dkg_session(*secret_addr) != *original_dkg_addr);
                    (network_state.cur_nodes, network_state.cur_threshold, network_state.epoch_duration_micros, option::none(), secrets_to_reshare)
                }
            };
            let signer_store = borrow_global<SignerStore>(@ace);
            let caller = signer_store.extend_ref.generate_signer_for_extending();
            let session = epoch_change::new_session(
                &caller,
                network_state.cur_nodes,
                network_state.cur_threshold,
                new_nodes,
                new_threshold,
                new_epoch_duration_micros,
                secrets_to_reshare,
                new_secret_scheme,
            );
            network_state.epoch_change_info = option::some(EpochChangeInfo {
                nxt_nodes: new_nodes,
                session,
            });
            network_state.pending_proposals = vector[];
        }
    }
}

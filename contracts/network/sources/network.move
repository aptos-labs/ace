/// A network node is supposed to do the following.
/// - Input includes a worker account, its private key, and a PKE decryption key.
/// - Fetch `State` every 5 secs.
/// - After each fetch,
///   - for every secret in `State.secrets`, ensure a UserRequestHandler has started, if myself is a current epoch node.
///     Otherwise, stop all UserRequestHandlers ever started since the beginning of this node process.
///   - for every secret in `State.dkgs_in_progress`, ensure a DKG client has started, if myself is a current epoch node.
///     Otherwise, try stop all DKG clients ever started since the beginning of this node process.
///   - for every `State.epoch_change_state.dkr_sessions`, ensure a DKR-SRC client has started, if myself is a current epoch node.
///     Otherwise, try stop all DKR-SRC clients ever started since the beginning of this node process.
///   - for every, `State.epoch_change_state.dkr_sessions`, ensure a DKR-DST client has started, if myself is a next epoch node.
///     Otherwise, try stop all DKR-DST clients ever started since the beginning of this node process.
///
module ace::network {
    use std::error;
    use ace::worker_config;
    use aptos_framework::timestamp;
    use ace::dkr;
    use std::option::{Option, Self};
    use ace::dkg;
    use ace::group;
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
    
    struct EpochChangeState has copy, drop, store {
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
        nxt_epoch_duration_micros: u64,
        dkg_session: Option<address>,
        dkr_sessions: vector<address>,
    }

    struct State has key {
        epoch: u64,
        epoch_start_time_micros: u64,
        epoch_duration_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<address>,
        pending_proposals: vector<address>,
        epoch_change_state: Option<EpochChangeState>,
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
    struct ProposalResolved has drop, store {
        addr: address,
    }

    #[view]
    public fun state_bcs(): vector<u8> {
        bcs::to_bytes(borrow_global<State>(@ace))
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
            epoch_change_state: option::none(),
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

    /// Start a new epoch change: clear pending proposals, start new DKR sessions, start new DKG session if needed.
    fun do_start_epoch_change(
        state: &mut State,
        new_nodes: vector<address>,
        new_threshold: u64,
        new_epoch_duration_micros: u64,
        old_secrets_to_untrack: vector<address>,
        new_secret_scheme: Option<u8>,
    ) {
        let signer_store = borrow_global<SignerStore>(@ace);
        let caller = signer_store.extend_ref.generate_signer_for_extending();

        state.pending_proposals = vector[];

        assert!(state.epoch_change_state.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        let dkr_sessions = state.secrets
            .filter(|secret_addr| {
                let original_dkg = original_dkg_session(*secret_addr);
                !old_secrets_to_untrack.contains(&original_dkg)
            }).map_ref(|secret_addr| {
                dkr::new_session(&caller, *secret_addr, new_nodes, new_threshold)
            });
        state.epoch_change_state = option::some(EpochChangeState {
            nxt_nodes: new_nodes,
            nxt_threshold: new_threshold,
            dkg_session: new_secret_scheme.map(|scheme| dkg::new_session(&caller, new_nodes, new_threshold, group::rand_element(scheme))),
            dkr_sessions,
            nxt_epoch_duration_micros: new_epoch_duration_micros,
        });
    }

    #[randomness]
    entry fun touch() {
        let state = borrow_global_mut<State>(@ace);
        let now_micros = timestamp::now_microseconds();
        if (state.epoch_change_state.is_some()) {
            let all_dkg_completed = state.epoch_change_state.borrow().dkg_session.is_none() || dkg::completed(*state.epoch_change_state.borrow().dkg_session.borrow());
            let all_dkr_completed = state.epoch_change_state.borrow().dkr_sessions.all(|session| dkr::completed(*session));
            if (all_dkg_completed && all_dkr_completed) {
                let EpochChangeState { nxt_nodes, nxt_threshold, dkr_sessions, dkg_session, nxt_epoch_duration_micros } = state.epoch_change_state.extract();
                let new_secrets = dkr_sessions;
                if (dkg_session.is_some()) new_secrets.push_back(dkg_session.destroy_some());
                state.epoch += 1;
                state.epoch_start_time_micros = now_micros;
                state.cur_nodes = nxt_nodes;
                state.cur_threshold = nxt_threshold;
                state.secrets = new_secrets;
                state.epoch_duration_micros = nxt_epoch_duration_micros;
            }
        } else {

            // if there is an over-threshold approved proposal, execute it and discard the others.
            let num_proposals = state.pending_proposals.length();
            for (i in 0..num_proposals) {
                let proposal_addr = state.pending_proposals[i];
                let proposal_state = borrow_global_mut<ProposalState>(proposal_addr);
                if (proposal_state.voters.length() >= state.cur_threshold) {
                    proposal_state.executed = true;
                    event::emit(ProposalResolved { addr: proposal_addr });
                    let (new_nodes, new_threshold, new_epoch_duration_micros, new_secret_scheme, old_secrets_to_untrack) = match (&proposal_state.proposal) {
                        Proposal::CommitteeChange { nodes, threshold } => {
                            (*nodes, *threshold, state.epoch_duration_micros, option::none(), vector[])
                        }
                        Proposal::ResharingIntervalUpdate { new_interval_secs } => {
                            (state.cur_nodes, state.cur_threshold, *new_interval_secs * 1_000_000, option::none(), vector[])
                        }
                        Proposal::NewSecret { scheme } => {
                            (state.cur_nodes, state.cur_threshold, state.epoch_duration_micros, option::some(*scheme), vector[])
                        }
                        Proposal::SecretDeactivation { original_dkg_addr } => {
                            (state.cur_nodes, state.cur_threshold, state.epoch_duration_micros, option::none(), vector[*original_dkg_addr])
                        }
                    };
                    do_start_epoch_change(
                        state,
                        new_nodes,
                        new_threshold,
                        new_epoch_duration_micros,
                        old_secrets_to_untrack,
                        new_secret_scheme,
                    );
                    return;
                }
            };

            // Auto epoch change: fire if epoch is stale and no blockers.
            if (now_micros - state.epoch_start_time_micros >= state.epoch_duration_micros) {
                let new_nodes = state.cur_nodes;
                let new_threshold = state.cur_threshold;
                let epoch_duration_micros = state.epoch_duration_micros;
                do_start_epoch_change(
                    state,
                    new_nodes,
                    new_threshold,
                    epoch_duration_micros,
                    vector[],
                    option::none(),
                );
            }
        }
    }

    entry fun new_proposal(proposer: &signer, proposal_bcs: vector<u8>) {
        let state = borrow_global_mut<State>(@ace);
        let proposer_addr = address_of(proposer);
        assert!(@ace == proposer_addr || state.cur_nodes.contains(&proposer_addr), error::permission_denied(E_ONLY_ADMIN_OR_CURRENT_NODE_CAN_PROPOSE));
        assert!(state.epoch_change_state.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
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
    }

    entry fun approve_proposal(reviewer: &signer, proposal_addr: address) {
        let network_state = borrow_global<State>(@ace);
        let reviewer_addr = address_of(reviewer);
        assert!(network_state.cur_nodes.contains(&reviewer_addr), error::permission_denied(E_ONLY_CURRENT_NODE_CAN_PROPOSE));
        assert!(network_state.pending_proposals.contains(&proposal_addr), error::invalid_argument(E_PROPOSAL_NOT_PENDING));

        let proposal_state = borrow_global_mut<ProposalState>(proposal_addr);
        assert!(proposal_state.epoch == network_state.epoch, error::invalid_argument(E_PROPOSAL_IS_NOT_CURRENT));
        assert!(!proposal_state.executed, error::invalid_argument(E_PROPOSAL_ALREADY_EXECUTED));
        assert!(!proposal_state.voters.contains(&reviewer_addr), error::invalid_argument(E_ALREADY_VOTED));
        proposal_state.voters.push_back(address_of(reviewer));
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
}

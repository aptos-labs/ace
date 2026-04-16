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

    const E_ONLY_ADMIN_CAN_DO_THIS: u64 = 1;
    const E_INVALID_NODE: u64 = 2;
    const E_EPOCH_CHANGE_ALREADY_IN_PROGRESS: u64 = 3;
    const E_DKGS_IN_PROGRESS: u64 = 4;
    const E_ALREADY_INITIALIZED: u64 = 5;

    struct EpochChangeState has copy, drop, store {
        nxt_nodes: vector<address>,
        nxt_threshold: u64,
        dkr_sessions: vector<address>,
    }

    struct State has key {
        epoch: u64,
        epoch_start_time_micros: u64,
        cur_nodes: vector<address>,
        cur_threshold: u64,
        secrets: vector<address>,
        dkgs_in_progress: vector<address>,
        epoch_change_state: Option<EpochChangeState>,
    }

    /// Stored at @ace after `initialize()`. Enables automatic epoch rotation.
    struct AutoEpochChanger has key {
        extend_ref: ExtendRef,
        epoch_duration_micros: u64,
    }

    #[view]
    public fun state_bcs(): vector<u8> {
        bcs::to_bytes(borrow_global<State>(@ace))
    }

    /// Call once, right after contract publish, to enable automatic epoch rotation.
    entry fun initialize(ace: &signer, epoch_duration_secs: u64) {
        assert!(@ace == address_of(ace), error::permission_denied(E_ONLY_ADMIN_CAN_DO_THIS));
        assert!(!exists<AutoEpochChanger>(@ace), error::already_exists(E_ALREADY_INITIALIZED));
        let object_ref = object::create_sticky_object(@ace);
        let extend_ref = object::generate_extend_ref(&object_ref);
        move_to(ace, AutoEpochChanger {
            extend_ref,
            epoch_duration_micros: epoch_duration_secs * 1_000_000,
        });
    }

    entry fun start_initial_epoch(ace: &signer, nodes: vector<address>, threshold: u64) {
        assert!(@ace == address_of(ace), error::invalid_argument(E_ONLY_ADMIN_CAN_DO_THIS));
        nodes.for_each(|node| {
            assert!(worker_config::has_pke_enc_key(node), error::invalid_argument(E_INVALID_NODE));
        });

        move_to(ace, State {
            epoch: 0,
            epoch_start_time_micros: timestamp::now_microseconds(),
            cur_nodes: nodes,
            cur_threshold: threshold,
            secrets: vector[],
            dkgs_in_progress: vector[],
            epoch_change_state: option::none(),
        });
    }

    fun do_start_epoch_change(
        caller: &signer,
        state: &mut State,
        new_nodes: vector<address>,
        new_threshold: u64,
    ) {
        assert!(state.epoch_change_state.is_none(), error::invalid_state(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        assert!(state.dkgs_in_progress.is_empty(), error::invalid_state(E_DKGS_IN_PROGRESS));
        state.epoch_change_state = option::some(EpochChangeState {
            nxt_nodes: new_nodes,
            nxt_threshold: new_threshold,
            dkr_sessions: state.secrets.map_ref(|secret_addr| {
                dkr::new_session(caller, *secret_addr, new_nodes, new_threshold)
            }),
        });
    }

    entry fun start_epoch_change(ace: &signer, new_nodes: vector<address>, new_threshold: u64) acquires State {
        assert!(@ace == address_of(ace), error::permission_denied(E_ONLY_ADMIN_CAN_DO_THIS));
        let state = borrow_global_mut<State>(@ace);
        do_start_epoch_change(ace, state, new_nodes, new_threshold);
    }

    entry fun touch() acquires State, AutoEpochChanger {
        let state = borrow_global_mut<State>(@ace);
        let now_micros = timestamp::now_microseconds();
        if (state.epoch_change_state.is_some()) {
            if (state.epoch_change_state.borrow().dkr_sessions.all(|session| dkr::completed(*session))) {
                let EpochChangeState { nxt_nodes, nxt_threshold, dkr_sessions } = state.epoch_change_state.extract();
                state.epoch += 1;
                state.epoch_start_time_micros = now_micros;
                state.cur_nodes = nxt_nodes;
                state.cur_threshold = nxt_threshold;
                state.secrets = dkr_sessions;
            }
        } else {
            state.dkgs_in_progress.filter(|dkg| dkg::completed(*dkg)).for_each(|dkg| {
                state.dkgs_in_progress.remove_value(&dkg);
                state.secrets.push_back(dkg);
            });

            // Auto epoch change: fire if epoch is stale and no blockers.
            if (exists<AutoEpochChanger>(@ace) && state.dkgs_in_progress.is_empty()) {
                let changer = borrow_global<AutoEpochChanger>(@ace);
                if (now_micros - state.epoch_start_time_micros >= changer.epoch_duration_micros) {
                    let virtual_signer = object::generate_signer_for_extending(&changer.extend_ref);
                    let new_nodes = state.cur_nodes.map_ref(|a| *a);
                    let new_threshold = state.cur_threshold;
                    do_start_epoch_change(&virtual_signer, state, new_nodes, new_threshold);
                }
            }
        }
    }

    #[randomness]
    entry fun new_secret(ace: &signer, scheme: u8) {
        assert!(@ace == address_of(ace), error::invalid_argument(E_ONLY_ADMIN_CAN_DO_THIS));
        let state = borrow_global_mut<State>(@ace);
        assert!(state.epoch_change_state.is_none(), error::invalid_argument(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        let dkg = dkg::new_session(ace, state.cur_nodes, state.cur_threshold, group::rand_element(scheme));
        state.dkgs_in_progress.push_back(dkg);
    }

    entry fun delete_secret(ace: &signer, secret_addr: address) {
        assert!(@ace == address_of(ace), error::invalid_argument(E_ONLY_ADMIN_CAN_DO_THIS));
        let state = borrow_global_mut<State>(@ace);
        assert!(state.epoch_change_state.is_none(), error::invalid_argument(E_EPOCH_CHANGE_ALREADY_IN_PROGRESS));
        state.secrets.remove_value(&secret_addr);
    }
}

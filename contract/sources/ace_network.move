// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// ACE Network Coordination Contract
///
/// Manages worker registration, epochs, secret proposals, DKG, and epoch changes
/// for the threshold IBE system.
///
/// Key design points:
///   - Epoch 0 is the first operational epoch (set by start_initial_epoch).
///   - Any committee member can propose a new secret or an epoch change; these
///     only proceed once ≥ threshold committee members approve.
///   - Multiple secret proposals can be active simultaneously.
///   - Only one epoch change proposal is allowed per epoch.
///   - When an epoch change is approved, all pending secret proposals are discarded.
///   - Secret shares NEVER appear on-chain (except the dummy_secret in test mode).
module admin::ace_network {
    use std::error;
    use std::signer::address_of;
    use std::string::String;
    use std::vector;
    use std::option::{Self, Option};
    use aptos_std::table::{Self, Table};
    use aptos_framework::object;
    use aptos_framework::event;

    // ============================================================================
    // Status codes
    // ============================================================================

    const STATUS_IN_PROGRESS: u8 = 0;
    const STATUS_DONE: u8 = 1;
    const STATUS_DISCARDED: u8 = 2;

    // ============================================================================
    // Error codes
    // ============================================================================

    const E_NOT_AUTHORITY: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_NOT_INITIALIZED: u64 = 3;
    const E_NODE_NOT_FOUND: u64 = 4;
    const E_NOT_COMMITTEE_MEMBER: u64 = 5;
    const E_DKG_NOT_FOUND: u64 = 6;
    const E_EPOCH_CHANGE_NOT_FOUND: u64 = 7;
    const E_SECRET_NOT_FOUND: u64 = 8;
    const E_INITIAL_EPOCH_ALREADY_SET: u64 = 9;
    const E_PROPOSAL_NOT_VOTING: u64 = 10;
    const E_PROPOSAL_STALE: u64 = 11;
    const E_ALREADY_APPROVED: u64 = 12;
    const E_EPOCH_CHANGE_PENDING: u64 = 13;

    // ============================================================================
    // Contribution format constants (first byte)
    // ============================================================================

    /// First byte of a "final" contribution blob.
    /// DKG final: [0x01][mpk_48][base_48][r_32] = 129 bytes total.
    /// Epoch change final: [0x01] = 1 byte.
    const CONTRIBUTION_FINAL_FLAG: u8 = 0x01;

    // ============================================================================
    // Data Structures
    // ============================================================================

    struct NodeInfo has copy, drop, store {
        endpoint: String,
        registered_epoch: u64,
    }

    struct EpochInfo has copy, drop, store {
        epoch_num: u64,
        nodes: vector<address>,
        threshold: u64,
    }

    /// Public-only secret info stored on-chain after a successful DKG.
    /// dummy_secret is the raw master scalar r — INSECURE, for testing only.
    struct SecretInfo has copy, drop, store {
        secret_id: u64,
        mpk: vector<u8>,        // 48-byte compressed G1 point
        base: vector<u8>,       // 48-byte compressed G1 point
        created_epoch: u64,
        dummy_secret: vector<u8>, // 32-byte LE Fr scalar (INSECURE: test-only)
    }

    struct DKGRecord has copy, drop, store {
        id: u64,
        epoch: u64,
        status: u8,
        contributions: vector<vector<u8>>,
    }

    struct SecretResharing has copy, drop, store {
        secret_id: u64,
        status: u8,
        contributions: vector<vector<u8>>,
    }

    struct EpochChangeRecord has copy, drop, store {
        id: u64,
        new_nodes: vector<address>,
        new_threshold: u64,
        status: u8,
        resharings: vector<SecretResharing>,
    }

    /// A proposal to create a new IBE secret, created as an Aptos Object.
    /// Becomes active (DKGRecord created) once ≥ threshold approvals are collected.
    struct SecretProposal has key {
        spec_bytes: vector<u8>,   // opaque: scheme + description
        proposer: address,
        created_epoch: u64,
        approvals: vector<address>,
        status: u8,               // STATUS_IN_PROGRESS | STATUS_DONE | STATUS_DISCARDED
    }

    /// A proposal to change the epoch committee, created as an Aptos Object.
    /// Only one may be pending at a time per epoch.
    struct EpochChangeProposal has key {
        new_nodes: vector<address>,
        new_threshold: u64,
        proposer: address,
        created_epoch: u64,
        approvals: vector<address>,
        status: u8,
    }

    struct NetworkState has key {
        authority: address,
        node_registry: Table<address, NodeInfo>,
        current_epoch_info: EpochInfo,
        secrets: vector<SecretInfo>,
        dkg_records: vector<DKGRecord>,
        epoch_change_records: vector<EpochChangeRecord>,
        next_dkg_id: u64,
        next_epoch_change_id: u64,
        /// Addresses of SecretProposal objects currently in voting or approved.
        pending_secret_proposals: vector<address>,
        /// Address of the one pending EpochChangeProposal, if any.
        pending_epoch_change_proposal_addr: Option<address>,
    }

    // ============================================================================
    // Events
    // ============================================================================

    #[event]
    struct SecretProposalCreated has drop, store {
        proposal_addr: address,
        proposer: address,
        created_epoch: u64,
    }

    #[event]
    struct EpochChangeProposalCreated has drop, store {
        proposal_addr: address,
        proposer: address,
        created_epoch: u64,
    }

    // ============================================================================
    // Entry Functions
    // ============================================================================

    /// Initialize the ACE network state. Must be called by the authority once.
    public entry fun initialize(authority: &signer) {
        let addr = address_of(authority);
        assert!(!exists<NetworkState>(addr), error::already_exists(E_ALREADY_INITIALIZED));
        move_to(authority, NetworkState {
            authority: addr,
            node_registry: table::new(),
            current_epoch_info: EpochInfo {
                epoch_num: 0,
                nodes: vector[],
                threshold: 0,
            },
            secrets: vector[],
            dkg_records: vector[],
            epoch_change_records: vector[],
            next_dkg_id: 0,
            next_epoch_change_id: 0,
            pending_secret_proposals: vector[],
            pending_epoch_change_proposal_addr: option::none(),
        });
    }

    /// Set epoch 0's committee. Can only be called once (when epoch is 0 and
    /// the committee is still empty). Authority-only.
    public entry fun start_initial_epoch(
        authority: &signer,
        initial_nodes: vector<address>,
        initial_threshold: u64,
    ) acquires NetworkState {
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(address_of(authority) == state.authority, error::permission_denied(E_NOT_AUTHORITY));
        assert!(
            state.current_epoch_info.epoch_num == 0 &&
            vector::is_empty(&state.current_epoch_info.nodes),
            error::invalid_state(E_INITIAL_EPOCH_ALREADY_SET)
        );
        state.current_epoch_info.nodes = initial_nodes;
        state.current_epoch_info.threshold = initial_threshold;
    }

    /// Node self-registers with its HTTP endpoint.
    /// Overwrites previous registration if called again.
    public entry fun register_node(node: &signer, endpoint: String) acquires NetworkState {
        let node_addr = address_of(node);
        let state = borrow_global_mut<NetworkState>(@admin);
        let epoch_num = state.current_epoch_info.epoch_num;
        let info = NodeInfo { endpoint, registered_epoch: epoch_num };
        if (table::contains(&state.node_registry, node_addr)) {
            *table::borrow_mut(&mut state.node_registry, node_addr) = info;
        } else {
            table::add(&mut state.node_registry, node_addr, info);
        };
    }

    /// Any committee member proposes a new IBE secret.
    /// Creates a SecretProposal object and emits SecretProposalCreated.
    /// DKG starts only after ≥ threshold approvals via approve_secret_proposal.
    public entry fun propose_new_secret(
        worker: &signer,
        spec_bytes: vector<u8>,
    ) acquires NetworkState {
        let worker_addr = address_of(worker);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(node_in_committee(state, worker_addr), error::permission_denied(E_NOT_COMMITTEE_MEMBER));
        let created_epoch = state.current_epoch_info.epoch_num;

        let constructor_ref = object::create_object(worker_addr);
        let proposal_addr = object::address_from_constructor_ref(&constructor_ref);
        let proposal_signer = object::generate_signer(&constructor_ref);
        move_to(&proposal_signer, SecretProposal {
            spec_bytes,
            proposer: worker_addr,
            created_epoch,
            approvals: vector[],
            status: STATUS_IN_PROGRESS,
        });

        vector::push_back(&mut state.pending_secret_proposals, proposal_addr);
        event::emit(SecretProposalCreated { proposal_addr, proposer: worker_addr, created_epoch });
    }

    /// Vote to approve a secret proposal. When ≥ threshold approvals are
    /// collected, a DKGRecord (InProgress) is created and workers can contribute.
    /// Rejected if the proposal's epoch no longer matches the current epoch.
    public entry fun approve_secret_proposal(
        worker: &signer,
        proposal_addr: address,
    ) acquires NetworkState, SecretProposal {
        let worker_addr = address_of(worker);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(node_in_committee(state, worker_addr), error::permission_denied(E_NOT_COMMITTEE_MEMBER));

        let proposal = borrow_global_mut<SecretProposal>(proposal_addr);
        assert!(proposal.status == STATUS_IN_PROGRESS, error::invalid_state(E_PROPOSAL_NOT_VOTING));
        assert!(proposal.created_epoch == state.current_epoch_info.epoch_num, error::invalid_state(E_PROPOSAL_STALE));
        assert!(!vector::contains(&proposal.approvals, &worker_addr), error::already_exists(E_ALREADY_APPROVED));

        vector::push_back(&mut proposal.approvals, worker_addr);

        if (vector::length(&proposal.approvals) >= state.current_epoch_info.threshold) {
            proposal.status = STATUS_DONE;
            let record = DKGRecord {
                id: state.next_dkg_id,
                epoch: state.current_epoch_info.epoch_num,
                status: STATUS_IN_PROGRESS,
                contributions: vector[],
            };
            state.next_dkg_id = state.next_dkg_id + 1;
            vector::push_back(&mut state.dkg_records, record);
        };
    }

    /// Submit a contribution to an in-progress DKG.
    /// The DKG record must belong to the current epoch; stale DKGs are rejected.
    ///
    /// Final contribution format: [0x01][mpk_48_bytes][base_48_bytes][r_32_bytes]
    /// When a final contribution is received, SecretInfo is created and DKG is marked Done.
    public entry fun contribute_to_dkg(
        caller: &signer,
        dkg_id: u64,
        contribution: vector<u8>,
    ) acquires NetworkState {
        let caller_addr = address_of(caller);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(
            caller_addr == state.authority || node_in_committee(state, caller_addr),
            error::permission_denied(E_NOT_COMMITTEE_MEMBER)
        );

        let current_epoch = state.current_epoch_info.epoch_num;
        let n = vector::length(&state.dkg_records);
        let found_idx = n;
        let i = 0;
        while (i < n) {
            let r = vector::borrow(&state.dkg_records, i);
            if (r.id == dkg_id && r.epoch == current_epoch && r.status == STATUS_IN_PROGRESS) {
                found_idx = i;
            };
            i = i + 1;
        };
        assert!(found_idx < n, error::not_found(E_DKG_NOT_FOUND));

        let record = vector::borrow_mut(&mut state.dkg_records, found_idx);
        vector::push_back(&mut record.contributions, contribution);

        if (is_final(&record.contributions)) {
            record.status = STATUS_DONE;
            let final_contrib = vector::borrow(&record.contributions, vector::length(&record.contributions) - 1);
            let mpk_bytes = vector::slice(final_contrib, 1, 49);
            let base_bytes = vector::slice(final_contrib, 49, 97);
            let r_bytes = vector::slice(final_contrib, 97, 129);
            let secret_id = vector::length(&state.secrets);
            vector::push_back(&mut state.secrets, SecretInfo {
                secret_id,
                mpk: mpk_bytes,
                base: base_bytes,
                created_epoch: current_epoch,
                dummy_secret: r_bytes,
            });
        };
    }

    /// Any committee member proposes an epoch change.
    /// Only one proposal is allowed while a prior proposal or EpochChangeRecord is in progress.
    /// Creates an EpochChangeProposal object and emits EpochChangeProposalCreated.
    public entry fun propose_epoch_change(
        worker: &signer,
        new_nodes: vector<address>,
        new_threshold: u64,
    ) acquires NetworkState {
        let worker_addr = address_of(worker);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(node_in_committee(state, worker_addr), error::permission_denied(E_NOT_COMMITTEE_MEMBER));
        // Only one epoch change process at a time (proposal or active resharing)
        assert!(
            option::is_none(&state.pending_epoch_change_proposal_addr) &&
            !epoch_change_in_progress(state),
            error::invalid_state(E_EPOCH_CHANGE_PENDING)
        );

        let created_epoch = state.current_epoch_info.epoch_num;
        let constructor_ref = object::create_object(worker_addr);
        let proposal_addr = object::address_from_constructor_ref(&constructor_ref);
        let proposal_signer = object::generate_signer(&constructor_ref);
        move_to(&proposal_signer, EpochChangeProposal {
            new_nodes,
            new_threshold,
            proposer: worker_addr,
            created_epoch,
            approvals: vector[],
            status: STATUS_IN_PROGRESS,
        });

        state.pending_epoch_change_proposal_addr = option::some(proposal_addr);
        event::emit(EpochChangeProposalCreated { proposal_addr, proposer: worker_addr, created_epoch });
    }

    /// Vote to approve an epoch change proposal. When ≥ threshold approvals are
    /// collected, the actual epoch change begins:
    ///   - If no secrets: committee and epoch advance immediately.
    ///   - If secrets exist: EpochChangeRecord (InProgress) created for DKR.
    /// All pending secret proposals are discarded on approval.
    public entry fun approve_epoch_change(
        worker: &signer,
        proposal_addr: address,
    ) acquires NetworkState, EpochChangeProposal, SecretProposal {
        let worker_addr = address_of(worker);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(node_in_committee(state, worker_addr), error::permission_denied(E_NOT_COMMITTEE_MEMBER));

        let proposal = borrow_global_mut<EpochChangeProposal>(proposal_addr);
        assert!(proposal.status == STATUS_IN_PROGRESS, error::invalid_state(E_PROPOSAL_NOT_VOTING));
        assert!(proposal.created_epoch == state.current_epoch_info.epoch_num, error::invalid_state(E_PROPOSAL_STALE));
        assert!(!vector::contains(&proposal.approvals, &worker_addr), error::already_exists(E_ALREADY_APPROVED));

        vector::push_back(&mut proposal.approvals, worker_addr);
        let threshold_reached = vector::length(&proposal.approvals) >= state.current_epoch_info.threshold;

        if (threshold_reached) {
            // Copy proposal data before mutating
            let new_nodes = proposal.new_nodes;
            let new_threshold = proposal.new_threshold;
            proposal.status = STATUS_DONE;

            // Clear the pending pointer
            state.pending_epoch_change_proposal_addr = option::none();

            // Discard any pending secret proposals from this epoch
            let pending_sps = state.pending_secret_proposals;
            state.pending_secret_proposals = vector[];
            let n = vector::length(&pending_sps);
            let i = 0;
            while (i < n) {
                let sp_addr = *vector::borrow(&pending_sps, i);
                let sp = borrow_global_mut<SecretProposal>(sp_addr);
                if (sp.status == STATUS_IN_PROGRESS) {
                    sp.status = STATUS_DISCARDED;
                };
                i = i + 1;
            };

            if (vector::is_empty(&state.secrets)) {
                // No secrets: advance epoch synchronously
                state.current_epoch_info.epoch_num = state.current_epoch_info.epoch_num + 1;
                state.current_epoch_info.nodes = new_nodes;
                state.current_epoch_info.threshold = new_threshold;
            } else {
                // Secrets exist: create resharing records (async DKR)
                let resharings = vector[];
                let num_secrets = vector::length(&state.secrets);
                let j = 0;
                while (j < num_secrets) {
                    let secret = vector::borrow(&state.secrets, j);
                    vector::push_back(&mut resharings, SecretResharing {
                        secret_id: secret.secret_id,
                        status: STATUS_IN_PROGRESS,
                        contributions: vector[],
                    });
                    j = j + 1;
                };
                let record = EpochChangeRecord {
                    id: state.next_epoch_change_id,
                    new_nodes,
                    new_threshold,
                    status: STATUS_IN_PROGRESS,
                    resharings,
                };
                state.next_epoch_change_id = state.next_epoch_change_id + 1;
                vector::push_back(&mut state.epoch_change_records, record);
            };
        };
    }

    /// Submit a contribution for a specific secret's resharing within an epoch change.
    /// When all resharings are done, the EpochChangeRecord is marked Done and epoch increments.
    public entry fun contribute_to_epoch_change(
        caller: &signer,
        epoch_change_id: u64,
        secret_id: u64,
        contribution: vector<u8>,
    ) acquires NetworkState {
        let caller_addr = address_of(caller);
        let state = borrow_global_mut<NetworkState>(@admin);
        assert!(
            caller_addr == state.authority || node_in_committee(state, caller_addr),
            error::permission_denied(E_NOT_COMMITTEE_MEMBER)
        );

        // Find the EpochChangeRecord
        let nec = vector::length(&state.epoch_change_records);
        let ec_idx = nec;
        let i = 0;
        while (i < nec) {
            if (vector::borrow(&state.epoch_change_records, i).id == epoch_change_id) {
                ec_idx = i;
            };
            i = i + 1;
        };
        assert!(ec_idx < nec, error::not_found(E_EPOCH_CHANGE_NOT_FOUND));

        // Find the SecretResharing within it
        let record = vector::borrow_mut(&mut state.epoch_change_records, ec_idx);
        let nr = vector::length(&record.resharings);
        let r_idx = nr;
        let j = 0;
        while (j < nr) {
            if (vector::borrow(&record.resharings, j).secret_id == secret_id) {
                r_idx = j;
            };
            j = j + 1;
        };
        assert!(r_idx < nr, error::not_found(E_SECRET_NOT_FOUND));

        let resharing = vector::borrow_mut(&mut record.resharings, r_idx);
        vector::push_back(&mut resharing.contributions, contribution);
        if (is_final(&resharing.contributions)) {
            resharing.status = STATUS_DONE;
        };

        // Check if all resharings are done
        let all_done = true;
        let k = 0;
        while (k < nr) {
            if (vector::borrow(&record.resharings, k).status != STATUS_DONE) {
                all_done = false;
            };
            k = k + 1;
        };

        if (all_done) {
            record.status = STATUS_DONE;
            // Advance epoch
            let new_nodes = record.new_nodes;
            let new_threshold = record.new_threshold;
            state.current_epoch_info.epoch_num = state.current_epoch_info.epoch_num + 1;
            state.current_epoch_info.nodes = new_nodes;
            state.current_epoch_info.threshold = new_threshold;
        };
    }

    // ============================================================================
    // View Functions
    // ============================================================================

    #[view]
    /// Returns (epoch_num, nodes, threshold) for the current epoch.
    public fun get_current_epoch(admin_addr: address): (u64, vector<address>, u64) acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        let e = &state.current_epoch_info;
        (e.epoch_num, e.nodes, e.threshold)
    }

    #[view]
    /// Returns (mpk_bytes, base_bytes, created_epoch, dummy_secret) for a secret.
    public fun get_secret(admin_addr: address, secret_id: u64): (vector<u8>, vector<u8>, u64, vector<u8>) acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        assert!(secret_id < vector::length(&state.secrets), error::not_found(E_SECRET_NOT_FOUND));
        let s = vector::borrow(&state.secrets, secret_id);
        (s.mpk, s.base, s.created_epoch, s.dummy_secret)
    }

    #[view]
    /// Returns the total number of secrets.
    public fun get_secret_count(admin_addr: address): u64 acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        vector::length(&state.secrets)
    }

    #[view]
    /// Returns the HTTP endpoint for a registered node.
    public fun get_node_endpoint(admin_addr: address, node_addr: address): String acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        assert!(table::contains(&state.node_registry, node_addr), error::not_found(E_NODE_NOT_FOUND));
        table::borrow(&state.node_registry, node_addr).endpoint
    }

    #[view]
    /// Returns true if addr is a member of the current committee.
    public fun is_committee_node(admin_addr: address, addr: address): bool acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        vector::contains(&state.current_epoch_info.nodes, &addr)
    }

    #[view]
    /// Returns (has_pending, dkg_id, epoch) for any in-progress DKG.
    public fun get_pending_dkg(admin_addr: address): (bool, u64, u64) acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        let n = vector::length(&state.dkg_records);
        let i = 0;
        while (i < n) {
            let record = vector::borrow(&state.dkg_records, i);
            if (record.status == STATUS_IN_PROGRESS) {
                return (true, record.id, record.epoch)
            };
            i = i + 1;
        };
        (false, 0, 0)
    }

    #[view]
    /// Returns (has_pending, epoch_change_id) for any in-progress EpochChangeRecord.
    public fun get_pending_epoch_change(admin_addr: address): (bool, u64) acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        let n = vector::length(&state.epoch_change_records);
        let i = 0;
        while (i < n) {
            let record = vector::borrow(&state.epoch_change_records, i);
            if (record.status == STATUS_IN_PROGRESS) {
                return (true, record.id)
            };
            i = i + 1;
        };
        (false, 0)
    }

    #[view]
    /// Returns the addresses of all pending (voting-phase) SecretProposal objects.
    public fun get_pending_secret_proposals(admin_addr: address): vector<address> acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        state.pending_secret_proposals
    }

    #[view]
    /// Returns (has_pending, proposal_addr) for the pending EpochChangeProposal, if any.
    public fun get_pending_epoch_change_proposal(admin_addr: address): (bool, address) acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        if (option::is_some(&state.pending_epoch_change_proposal_addr)) {
            (true, *option::borrow(&state.pending_epoch_change_proposal_addr))
        } else {
            (false, @0x0)
        }
    }

    #[view]
    /// Returns the secret_ids of pending (InProgress) resharings within an epoch change.
    public fun get_pending_resharing_secret_ids(admin_addr: address, epoch_change_id: u64): vector<u64> acquires NetworkState {
        let state = borrow_global<NetworkState>(admin_addr);
        let n = vector::length(&state.epoch_change_records);
        let i = 0;
        while (i < n) {
            let record = vector::borrow(&state.epoch_change_records, i);
            if (record.id == epoch_change_id) {
                let result = vector[];
                let nr = vector::length(&record.resharings);
                let j = 0;
                while (j < nr) {
                    let resharing = vector::borrow(&record.resharings, j);
                    if (resharing.status == STATUS_IN_PROGRESS) {
                        vector::push_back(&mut result, resharing.secret_id);
                    };
                    j = j + 1;
                };
                return result
            };
            i = i + 1;
        };
        vector[]
    }

    // ============================================================================
    // Internal Helpers
    // ============================================================================

    fun node_in_committee(state: &NetworkState, addr: address): bool {
        vector::contains(&state.current_epoch_info.nodes, &addr)
    }

    fun epoch_change_in_progress(state: &NetworkState): bool {
        let n = vector::length(&state.epoch_change_records);
        let i = 0;
        while (i < n) {
            if (vector::borrow(&state.epoch_change_records, i).status == STATUS_IN_PROGRESS) {
                return true
            };
            i = i + 1;
        };
        false
    }

    /// Returns true if the last contribution in the vector has the final flag set.
    fun is_final(contributions: &vector<vector<u8>>): bool {
        let n = vector::length(contributions);
        if (n == 0) return false;
        let last = vector::borrow(contributions, n - 1);
        !vector::is_empty(last) && *vector::borrow(last, 0) == CONTRIBUTION_FINAL_FLAG
    }
}

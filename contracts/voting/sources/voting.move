module ace::voting {
    use std::signer::address_of;
    use std::vector::range;
    use std::error;
    use aptos_framework::object;
    use aptos_framework::event;

    const E_SESSION_NOT_ACCEPTING_VOTES: u64 = 1;
    const E_NOT_A_QUALIFIED_VOTER: u64 = 2;
    const E_ALREADY_VOTED: u64 = 3;
    const E_ONLY_OWNER_CAN_CANCEL: u64 = 4;

    const STATE__ACCEPTING_VOTES: u8 = 0;
    const STATE__PASSED: u8 = 1;
    const STATE__CANCELLED: u8 = 2;

    struct Session has key {
        owner: address,
        qualified_voters: vector<address>,
        threshold: u64,
        state_code: u8,
        votes: vector<bool>,
    }

    #[event]
    struct SessionCreated has drop, store {
        session_addr: address,
    }
    
    #[event]
    struct SessionCompleted has drop, store {
        session_addr: address,
    }

    #[event]
    struct SessionCancelled has drop, store {
        session_addr: address,
    }

    public fun new_session(owner: &signer, qualified_voters: vector<address>, threshold: u64): address {
        let owner_addr = address_of(owner);
        let session = Session {
            owner: owner_addr,
            qualified_voters,
            threshold,
            state_code: STATE__ACCEPTING_VOTES,
            votes: range(0, qualified_voters.length()).map(|_| false),
        };
        let object_ref = object::create_sticky_object(owner_addr);
        let object_signer = object_ref.generate_signer();
        move_to(&object_signer, session);
        let session_addr = object_ref.address_from_constructor_ref();
        event::emit(SessionCreated { session_addr });
        session_addr
    }

    public entry fun vote(voter: &signer, proposal_addr: address) {
        let session = borrow_global_mut<Session>(proposal_addr);
        assert!(session.state_code == STATE__ACCEPTING_VOTES, error::invalid_state(E_SESSION_NOT_ACCEPTING_VOTES));
        let (voter_found, voter_idx) = session.qualified_voters.find(|qv| *qv == address_of(voter));
        assert!(voter_found, error::permission_denied(E_NOT_A_QUALIFIED_VOTER));
        assert!(!session.votes[voter_idx], error::invalid_state(E_ALREADY_VOTED));
        session.votes[voter_idx] = true;
    }

    public fun cancel(owner: &signer, proposal_addr: address) {
        let session = borrow_global_mut<Session>(proposal_addr);
        assert!(session.owner == address_of(owner), error::permission_denied(E_ONLY_OWNER_CAN_CANCEL));
        assert!(session.state_code == STATE__ACCEPTING_VOTES, error::invalid_state(E_SESSION_NOT_ACCEPTING_VOTES));
        session.state_code = STATE__CANCELLED;
    }

    public fun touch(proposal_addr: address) {
        let session = borrow_global_mut<Session>(proposal_addr);
        if (session.state_code == STATE__ACCEPTING_VOTES) {
            let num_votes = session.votes.filter(|v| *v).length();
            if (num_votes >= session.threshold) {
                session.state_code = STATE__PASSED;
            }
        }
    }

    public fun completed(proposal_addr: address): bool {
        if (!exists<Session>(proposal_addr)) return false;
        let session = borrow_global<Session>(proposal_addr);
        session.state_code == STATE__PASSED
    }

    /// Returns (votes, threshold) for external view composition (e.g. network::state_view_v0_bcs).
    public fun session_votes_and_threshold(session_addr: address): (vector<bool>, u64) acquires Session {
        let session = borrow_global<Session>(session_addr);
        (session.votes, session.threshold)
    }
}
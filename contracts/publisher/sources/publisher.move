module ace::publisher {
    use std::error;
    use std::option::{Self, Option};
    use aptos_framework::account::{Self, SignerCapability};
    use aptos_framework::code;
    use aptos_framework::resource_account;
    use aptos_framework::transaction_context;

    const E_NOT_ACE_SIGNER: u64 = 1;
    const E_NOT_INITIAL_MULTISIG: u64 = 2;
    const E_NOT_MULTISIG_EXECUTION: u64 = 3;
    const E_BOOTSTRAP_CLOSED: u64 = 4;
    const E_WRONG_SIGNER_CAPABILITY: u64 = 5;

    /// Created once during the first package publication, then moved to network::init_module.
    /// Only the holder can request an @ace signer or publish after bootstrap.
    struct HandoffCap has store {}

    struct Publisher has key {
        ace_signer_cap: SignerCapability,
        handoff_cap: Option<HandoffCap>,
    }

    /// The first ACE package is published by the initial native multisig through
    /// resource_account::create_resource_account_and_publish_package. That function
    /// stores @ace's signer capability under the initial multisig before init_module runs.
    fun init_module(ace_signer: &signer) {
        assert!(ace_signer.address_of() == @ace, error::permission_denied(E_NOT_ACE_SIGNER));
        let ace_signer_cap = resource_account::retrieve_resource_account_cap(
            ace_signer,
            @initial_multisig,
        );
        assert!(
            account::get_signer_capability_address(&ace_signer_cap) == @ace,
            error::invalid_state(E_WRONG_SIGNER_CAPABILITY),
        );
        move_to(ace_signer, Publisher {
            ace_signer_cap,
            handoff_cap: option::some(HandoffCap {}),
        });
    }

    public fun initial_multisig(): address {
        @initial_multisig
    }

    /// Only @ace's publication-time signer can take the one-shot handoff token.
    /// Publish network last; its init_module takes the token and closes bootstrap.
    public fun take_handoff_cap(ace_signer: &signer): HandoffCap {
        assert!(ace_signer.address_of() == @ace, error::permission_denied(E_NOT_ACE_SIGNER));
        let publisher = &mut Publisher[@ace];
        assert!(publisher.handoff_cap.is_some(), error::invalid_state(E_BOOTSTRAP_CLOSED));
        publisher.handoff_cap.extract()
    }

    /// Temporary publication path for the packages needed before network exists.
    /// Pending initial-multisig proposals lose access once network takes HandoffCap.
    public entry fun bootstrap_publish(
        admin: &signer,
        metadata_serialized: vector<u8>,
        modules: vector<vector<u8>>,
    ) {
        assert!(
            admin.address_of() == @initial_multisig,
            error::permission_denied(E_NOT_INITIAL_MULTISIG),
        );
        assert!(
            transaction_context::is_multisig_payload_txn(),
            error::permission_denied(E_NOT_MULTISIG_EXECUTION),
        );
        let publisher = &Publisher[@ace];
        assert!(publisher.handoff_cap.is_some(), error::permission_denied(E_BOOTSTRAP_CLOSED));
        let ace_signer = account::create_signer_with_capability(&publisher.ace_signer_cap);
        code::publish_package_txn(&ace_signer, metadata_serialized, modules);
    }

    /// Network stores HandoffCap in a private resource and uses this signer for
    /// resources that must live at @ace. A reference to HandoffCap cannot be forged.
    public fun ace_signer(_handoff_cap: &HandoffCap): signer {
        account::create_signer_with_capability(&Publisher[@ace].ace_signer_cap)
    }

    /// Post-bootstrap publishing is possible only through the HandoffCap holder.
    /// Network is responsible for checking its active governance multisig and epoch policy.
    public fun publish_with_cap(
        handoff_cap: &HandoffCap,
        metadata_serialized: vector<u8>,
        modules: vector<vector<u8>>,
    ) {
        let signer = ace_signer(handoff_cap);
        code::publish_package_txn(&signer, metadata_serialized, modules);
    }
}

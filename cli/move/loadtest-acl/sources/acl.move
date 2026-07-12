module loadtest::acl {
    use std::string::String;

    #[view]
    public fun on_ace_vrf_request(_label: vector<u8>, _account: address, _origin: String): bool {
        true
    }
}

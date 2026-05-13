module loadtest::acl {
    #[view]
    public fun check_permission(_user: address, _domain: vector<u8>): bool {
        true
    }
}

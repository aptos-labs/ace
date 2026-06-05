// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

module admin::threshold_vrf_origin_demo {
    use std::string::{String, utf8};

    #[view]
    public fun on_ace_vrf_request(_label: vector<u8>, _account: address, origin: String): bool {
        origin == utf8(b"https://shelby.example")
    }
}

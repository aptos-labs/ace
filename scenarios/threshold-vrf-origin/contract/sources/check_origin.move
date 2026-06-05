// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

module admin::threshold_vrf_origin_demo {
    use std::string::{String, utf8};

    #[view]
    public fun check_request_origin(origin: String): bool {
        origin == utf8(b"https://shelby.example")
    }
}

// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shared constants for ACE worker / protocol packages (epoch status, crypto formats).
module ace::worker_config {
    use std::string::String;

    struct Endpoint has key {
        endpoint: String,
    }

    struct PkeEncryptionKey has key {
        bytes: vector<u8>,
    }

    public entry fun register_endpoint(worker: &signer, endpoint: String) {
        move_to(worker, Endpoint { endpoint });
    }

    public entry fun register_pke_enc_key(worker: &signer, bytes: vector<u8>) {
        move_to(worker, PkeEncryptionKey { bytes });
    }

    public fun has_pke_enc_key(worker: address): bool {
        exists<PkeEncryptionKey>(worker)
    }
}

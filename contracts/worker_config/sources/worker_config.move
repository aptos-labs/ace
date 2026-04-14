// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shared constants for ACE worker / protocol packages (epoch status, crypto formats).
module ace::worker_config {
    use std::string::String;
    use ace::pke;

    struct Endpoint has key {
        endpoint: String,
    }

    struct PkeEncryptionKey has key {
        ek: pke::EncryptionKey,
    }

    public entry fun register_endpoint(worker: &signer, endpoint: String) {
        move_to(worker, Endpoint { endpoint });
    }

    public entry fun register_pke_enc_key(worker: &signer, bytes: vector<u8>) {
        let ek = pke::enc_key_from_bytes(bytes);
        move_to(worker, PkeEncryptionKey { ek });
    }

    public fun has_pke_enc_key(worker: address): bool {
        exists<PkeEncryptionKey>(worker)
    }
}

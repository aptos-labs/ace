// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shared constants for ACE worker / protocol packages (epoch status, crypto formats).
module ace::worker_config {
    use std::bcs;
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

    /// Return BCS encoding of the worker's PKE encryption key.
    /// Output: [u8 variant=0x00][u8 ULEB128(32)][32B enc_base][u8 ULEB128(32)][32B public_point] = 67 bytes.
    /// Compatible with ts-sdk `pke.EncryptionKey.fromBytes()` and `vss-common` `pke::EncryptionKey::from_bytes()`.
    #[view]
    public fun get_pke_enc_key_bcs(worker: address): vector<u8> acquires PkeEncryptionKey {
        bcs::to_bytes(&borrow_global<PkeEncryptionKey>(worker).ek)
    }
}

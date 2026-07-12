// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shared constants for ACE worker / protocol packages (epoch status, crypto formats).
module ace::worker_config {
    use std::bcs;
    use std::string;
    use std::string::String;
    use ace::pke;
    use ace::sig;

    struct ClientEndpoint has key {
        endpoint: String,
    }

    struct NodeMsgEndpoint has key {
        endpoint: String,
    }

    struct PkeEncryptionKey has key {
        ek: pke::EncryptionKey,
    }

    struct SigVerificationKey has key {
        pk: sig::PublicKey,
    }

    public entry fun register_client_endpoint(worker: &signer, endpoint: String) {
        move_to(worker, ClientEndpoint { endpoint });
    }

    public entry fun register_node_msg_endpoint(worker: &signer, endpoint: String) {
        move_to(worker, NodeMsgEndpoint { endpoint });
    }

    public entry fun register_pke_enc_key(worker: &signer, bytes: vector<u8>) {
        let ek = pke::enc_key_from_bytes(bytes);
        move_to(worker, PkeEncryptionKey { ek });
    }

    public entry fun register_sig_verification_key(worker: &signer, bytes: vector<u8>) {
        let pk = sig::public_key_from_bytes(bytes);
        move_to(worker, SigVerificationKey { pk });
    }

    public fun has_pke_enc_key(worker: address): bool {
        exists<PkeEncryptionKey>(worker)
    }

    public fun has_client_endpoint(worker: address): bool {
        exists<ClientEndpoint>(worker)
    }

    public fun has_sig_verification_key(worker: address): bool {
        exists<SigVerificationKey>(worker)
    }

    public fun has_node_msg_endpoint(worker: address): bool {
        exists<NodeMsgEndpoint>(worker)
    }

    #[view]
    /// Return the worker's registered client-facing endpoint string.
    public fun get_client_endpoint(worker: address): String {
        ClientEndpoint[worker].endpoint
    }

    #[view]
    /// Return the worker's registered node-to-node message endpoint string.
    public fun get_node_msg_endpoint(worker: address): String {
        NodeMsgEndpoint[worker].endpoint
    }

    #[view]
    /// Return BCS encoding of the worker's PKE encryption key.
    /// Output: [u8 variant=0x00][u8 ULEB128(32)][32B enc_base][u8 ULEB128(32)][32B public_point] = 67 bytes.
    /// Compatible with ts-sdk `pke.EncryptionKey.fromBytes()` and `vss-common` `pke::EncryptionKey::from_bytes()`.
    public fun get_pke_enc_key_bcs(worker: address): vector<u8> {
        bcs::to_bytes(&PkeEncryptionKey[worker].ek)
    }

    #[view]
    /// Return BCS encoding of the worker's node-to-node signature public key.
    public fun get_sig_verification_key_bcs(worker: address): vector<u8> {
        bcs::to_bytes(&SigVerificationKey[worker].pk)
    }

    #[test(worker = @0x123)]
    fun register_client_endpoint_round_trip(worker: signer) {
        let endpoint = string::utf8(b"http://127.0.0.1:8000");
        register_client_endpoint(&worker, endpoint);
        assert!(has_client_endpoint(@0x123), 1);
        assert!(get_client_endpoint(@0x123) == endpoint, 2);
    }

    #[test(worker = @0x123)]
    fun register_sig_verification_key_round_trip(worker: signer) {
        let pk_bytes = x"0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        register_sig_verification_key(&worker, pk_bytes);
        assert!(has_sig_verification_key(@0x123), 1);
        assert!(get_sig_verification_key_bcs(@0x123) == pk_bytes, 2);
    }

    #[test(worker = @0x123)]
    fun register_node_msg_endpoint_round_trip(worker: signer) {
        let endpoint = string::utf8(b"http://127.0.0.1:9000");
        register_node_msg_endpoint(&worker, endpoint);
        assert!(has_node_msg_endpoint(@0x123), 1);
        assert!(get_node_msg_endpoint(@0x123) == endpoint, 2);
    }
}

// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shared constants for ACE worker / protocol packages (epoch status, crypto formats).
module ace::worker_config {
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

    #[test(worker = @0x123)]
    fun register_client_endpoint_round_trip(worker: signer) {
        let endpoint = std::string::utf8(b"http://127.0.0.1:8000");
        register_client_endpoint(&worker, endpoint);
        assert!(has_client_endpoint(@0x123), 1);
        assert!(ClientEndpoint[@0x123].endpoint == endpoint, 2);
    }

    #[test(worker = @0x123)]
    fun register_sig_verification_key_round_trip(worker: signer) {
        let pk_bytes = x"0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        register_sig_verification_key(&worker, pk_bytes);
        assert!(has_sig_verification_key(@0x123), 1);
        let pk = SigVerificationKey[@0x123].pk;
        assert!(sig::public_key_scheme(&pk) == sig::scheme_ed25519(), 2);
        let inner = sig::public_key_as_ed25519(pk);
        assert!(
            ace::sig_ed25519::public_key_bytes(&inner) ==
                x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            3,
        );
    }

    #[test(worker = @0x123)]
    fun register_node_msg_endpoint_round_trip(worker: signer) {
        let endpoint = std::string::utf8(b"http://127.0.0.1:9000");
        register_node_msg_endpoint(&worker, endpoint);
        assert!(has_node_msg_endpoint(@0x123), 1);
        assert!(NodeMsgEndpoint[@0x123].endpoint == endpoint, 2);
    }
}

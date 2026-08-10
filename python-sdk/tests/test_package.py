# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

import hashlib

from aptos_sdk.account_address import AccountAddress
from py_ecc.bls.hash_to_curve import hash_to_G1

import ace_sdk
from ace_sdk import (
    admin_recovery,
    decryption,
    group,
    ibe_aptos,
    known_deployments,
    network,
    pke,
    sig,
    t_ibe,
    vrf_aptos,
    vss,
)
from ace_sdk._internal.common import ContractID, FullDecryptionDomain
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal import discovery
from ace_sdk.bcs import Serializer, serialize_account_address
from ace_sdk.group import bls12381g1, bls12381g2
from ace_sdk.result import Result


def test_top_level_exports_common_modules() -> None:
    assert ace_sdk.pke is pke
    assert ace_sdk.network is network
    assert ace_sdk.sig is sig
    assert ace_sdk.admin_recovery is admin_recovery
    assert ace_sdk.decryption is decryption
    assert ace_sdk.vrf_aptos is vrf_aptos
    assert hasattr(ace_sdk, "Result")


def test_known_deployments_match_ts_registry_shape() -> None:
    deployment = known_deployments.known_deployments["shelbynet-20260731"]

    assert deployment.chain_id == 118
    assert deployment.ace_deployment.api_endpoint == "https://api.shelbynet.shelby.xyz/v1"
    assert (
        deployment.ace_deployment.discovery_url
        == "https://ace-discovery-646682240579.us-central1.run.app"
    )
    assert str(deployment.ibe_keypair_id) == (
        "0xa36e6db16b015c6c2c9a376afe3075b11031ee0df393c226e7d599f615759a17"
    )

    with_key = deployment.with_api_key("secret")
    assert with_key.ace_deployment.api_key == "secret"
    assert with_key.ace_deployment.discovery_url == deployment.ace_deployment.discovery_url
    assert deployment.ace_deployment.api_key is None

    with_client_config = with_key.with_client_config({"headers": {"x-test": "1"}})
    assert with_client_config.ace_deployment.api_key == "secret"
    assert with_client_config.ace_deployment.client_config == {"headers": {"x-test": "1"}}


def test_network_usage_and_state_wire_decode() -> None:
    assert network.usage_for_primitive(network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD) == 2
    assert network.scheme_name(1).endswith("(default)")

    node = AccountAddress.from_str("0x1")
    secret_session = AccountAddress.from_str("0x2")
    keypair_id = AccountAddress.from_str("0x3")

    serializer = Serializer()
    serializer.serialize_u64(7)
    serializer.serialize_u64(100)
    serializer.serialize_u64(200)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, node)
    serializer.serialize_u64(1)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, secret_session)
    serialize_account_address(serializer, keypair_id)
    serializer.serialize_u8(network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD)
    serializer.serialize_u64(network.USAGE_BFIBE_BLS12381_SHORTSIG_AEAD)
    serializer.serialize_str("ibe")
    serializer.serialize_u32_as_uleb128(1)
    serializer.serialize_u8(0)
    serializer.serialize_u8(0)

    state = network.State.from_bytes(serializer.to_bytes()).unwrap_or_throw("state")

    assert state.epoch == 7
    assert state.cur_threshold == 1
    assert state.secrets[0].scheme_name().endswith("(default)")
    assert state.active_proposals() == []
    assert not state.is_epoch_changing()


def test_pke_hpke_round_trip_default_scheme() -> None:
    encryption_key, decryption_key = pke.keygen()
    plaintext = b"hello pke"

    ciphertext = pke.encrypt(encryption_key, plaintext)
    decrypted = pke.decrypt(decryption_key, ciphertext)

    assert decrypted.is_ok
    assert decrypted.ok_value == plaintext


def test_pke_elgamal_golden_vector_and_hex_roundtrip() -> None:
    golden_dec_key = bytes.fromhex(
        "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174"
        "120d2874c3b7e5d7576c64b8a346b84159100ad978864319e880c249a54ae5d3708"
    )
    golden_enc_key_hex = (
        "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174"
        "1209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71"
    )
    golden_ciphertext = bytes.fromhex(
        "0020ec9d964805902bc6966b04ef1d54e655bb4356ad67029958e4af28b3dab49563"
        "20fe2416a85535cbd637b93487527a6427a0c632d6c66d3b3f71d82d625f3ba07e"
        "107b7b4a4ec372436a02589fe86b5d0eff2080b95f09e629565a296a7dcaadba664"
        "8f8f286633c9747774e453f5b2427540d"
    )

    decryption_key = pke.DecryptionKey.from_bytes(golden_dec_key).unwrap_or_throw("dk")
    ciphertext = pke.Ciphertext.from_bytes(golden_ciphertext).unwrap_or_throw("ct")
    encryption_key = pke.derive_encryption_key(decryption_key)

    assert encryption_key.to_hex() == golden_enc_key_hex
    assert pke.DecryptionKey.from_hex("0x" + decryption_key.to_hex()).is_ok
    assert pke.decrypt(decryption_key, ciphertext).unwrap_or_throw("decrypt") == b"golden-plaintext"
    assert not pke.Ciphertext.from_bytes(golden_ciphertext + b"\x00").is_ok


def test_sig_ed25519_round_trip_and_bcs_hex() -> None:
    signing_key = sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32)))
    public_key = signing_key.public_key()
    message = b"hello sig"
    signature = signing_key.sign(message)

    assert sig.verify(message, signature, public_key)
    assert not sig.verify(b"wrong", signature, public_key)
    assert public_key.to_bytes()[:2] == b"\x00\x20"
    assert signature.to_bytes()[:2] == b"\x00\x40"
    assert signing_key.to_bytes() == b"\x00\x20" + bytes(range(32))
    assert sig.PublicKey.from_hex("0x" + public_key.to_hex()).unwrap_or_throw("pk").to_bytes() == public_key.to_bytes()
    assert sig.Signature.from_hex(signature.to_hex()).unwrap_or_throw("sig").to_bytes() == signature.to_bytes()
    assert sig.SigningKey.from_hex(signing_key.to_hex()).unwrap_or_throw("sk").public_key().to_bytes() == public_key.to_bytes()
    assert not sig.SigningKey.from_bytes(signing_key.to_bytes() + b"\x00").is_ok


def test_vss_public_api_reconstructs_g2_shares() -> None:
    secret = b"\x42" + bytes(31)
    share_bytes = bls12381g2.split(secret, threshold=3, total=5).unwrap_or_throw("split")

    indexed_shares = []
    for i in [0, 2, 4]:
        share = bls12381g2.SecretShare.from_bigint(
            int.from_bytes(share_bytes[i], "little")
        ).unwrap_or_throw("share")
        indexed_shares.append((i + 1, vss.SecretShare(group.SCHEME_BLS12381G2, share)))

    recovered = vss.reconstruct(indexed_shares).unwrap_or_throw("reconstruct")

    assert recovered.scheme == group.SCHEME_BLS12381G2
    assert recovered.inner.scalar == 0x42


def test_tibe_admin_extract_decrypts_production_ciphertext() -> None:
    identity = b"admin-recovery-label"
    plaintext = b"reconstructed master secret works"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")

    ciphertext = t_ibe.encrypt(mpk, identity, plaintext).unwrap_or_throw("encrypt")
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=identity).unwrap_or_throw("extract")
    restored_idk = t_ibe.IdentityDecryptionKeyShare.from_hex(
        "0x" + idk.to_hex()
    ).unwrap_or_throw("idk hex")
    restored_ct = t_ibe.Ciphertext.from_hex("0x" + ciphertext.to_hex()).unwrap_or_throw("ct hex")

    decrypted = t_ibe.decrypt([restored_idk], restored_ct).unwrap_or_throw("decrypt")

    assert decrypted == plaintext
    assert not t_ibe.extract(
        scheme=t_ibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        msk_scalar=msk.inner.scalar,
        identity=identity,
    ).is_ok


def test_ibe_aptos_encrypt_uses_full_decryption_domain() -> None:
    keypair_id = AccountAddress.from_str(
        "0x00000000000000000000000000000000000000000000000000000000000000c1"
    )
    module_addr = AccountAddress.from_str("0x1")
    label = b"object-id"
    plaintext = b"aptos ibe plaintext"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )

    ciphertext_bytes = ibe_aptos.encrypt(
        ace_deployment=deployment,
        keypair_id=keypair_id,
        chain_id=42,
        module_addr=module_addr,
        module_name="example",
        label=label,
        plaintext=plaintext,
        pk=mpk,
    ).unwrap_or_throw("encrypt")

    ciphertext = t_ibe.Ciphertext.from_bytes(ciphertext_bytes).unwrap_or_throw("ct")
    fdd = FullDecryptionDomain(
        keypair_id,
        ContractID.new_aptos(42, module_addr, "example"),
        label,
    )
    assert FullDecryptionDomain.from_hex("0x" + fdd.to_hex()).unwrap_or_throw("fdd").to_bytes() == fdd.to_bytes()
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=fdd.to_bytes()).unwrap_or_throw("idk")

    assert t_ibe.decrypt([idk], ciphertext).unwrap_or_throw("decrypt") == plaintext


def test_ibe_aptos_fetch_pk_can_read_discovery_snapshot(monkeypatch) -> None:
    keypair_id = AccountAddress.from_str(
        "0x00000000000000000000000000000000000000000000000000000000000000c1"
    )
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    base = group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point))
    result_pk = group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))

    serializer = Serializer()
    serializer.serialize_u64(0)
    serializer.serialize_u64(0)
    serializer.serialize_u64(0)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u64(0)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u8(0)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, keypair_id)
    base.serialize(serializer)
    result_pk.serialize(serializer)
    serializer.serialize_u32_as_uleb128(0)
    body = "0x" + serializer.to_bytes().hex()

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return body.encode("utf-8")

    monkeypatch.setattr(discovery, "urlopen", lambda _url: Response())
    deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
        discovery_url="https://discovery.example/",
    )

    fetched = ibe_aptos.fetch_pk(deployment, keypair_id).unwrap_or_throw("fetch pk")

    assert fetched.to_hex() == mpk.to_hex()


def test_discovery_view_decodes_snapshot_and_readable_projection() -> None:
    node_a = AccountAddress.from_str(
        "0x000000000000000000000000000000000000000000000000000000000000000a"
    )
    node_b = AccountAddress.from_str(
        "0x000000000000000000000000000000000000000000000000000000000000000b"
    )
    session_addr = AccountAddress.from_str(
        "0x00000000000000000000000000000000000000000000000000000000000000c1"
    )
    golden_enc_key = pke.EncryptionKey.from_hex(
        "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174"
        "1209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71"
    ).unwrap_or_throw("enc key")
    element = group.Element.from_bls12381_g2(bls12381g2.g2_generator())

    serializer = Serializer()
    serializer.serialize_u64(9)
    serializer.serialize_u64(100)
    serializer.serialize_u64(200)
    serializer.serialize_u32_as_uleb128(2)
    serialize_account_address(serializer, node_a)
    serialize_account_address(serializer, node_b)
    serializer.serialize_u64(1)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, session_addr)
    serialize_account_address(serializer, session_addr)
    serializer.serialize_u8(network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD)
    serializer.serialize_u64(network.USAGE_BFIBE_BLS12381_SHORTSIG_AEAD)
    serializer.serialize_str("production ibe")
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u8(0)

    serializer.serialize_u32_as_uleb128(2)
    serialize_account_address(serializer, node_a)
    serializer.serialize_u8(1)
    serializer.serialize_str("https://node-a.example/")
    golden_enc_key.serialize(serializer)
    serialize_account_address(serializer, node_b)
    serializer.serialize_u8(0)
    golden_enc_key.serialize(serializer)

    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, session_addr)
    element.serialize(serializer)
    element.serialize(serializer)
    serializer.serialize_u32_as_uleb128(2)
    element.serialize(serializer)
    element.serialize(serializer)

    view = discovery.DiscoveryViewV0.from_bytes(serializer.to_bytes())
    readable = view.to_readable()

    assert view.state.epoch == 9
    assert view.nodes["0x" + node_a.address.hex()]["endpoint"] == "https://node-a.example/"
    assert view.sessions["0x" + session_addr.address.hex()].base_point.equals(element)
    assert readable["nodes"][0]["pkeEncKey"] == golden_enc_key.to_hex()
    assert readable["keypairs"][0]["masterPublicKey"] == element.to_hex()

    try:
        discovery.DiscoveryViewV0.from_bytes(serializer.to_bytes() + b"\x00")
    except ValueError as err:
        assert "trailing bytes" in str(err)
    else:
        raise AssertionError("expected trailing bytes rejection")


def test_discovery_chain_reader_reuses_snapshot(monkeypatch) -> None:
    node = AccountAddress.from_str("0xa")
    enc_key, _ = pke.keygen()
    serializer = Serializer()
    serializer.serialize_u64(0)
    serializer.serialize_u64(0)
    serializer.serialize_u64(0)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, node)
    serializer.serialize_u64(1)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u32_as_uleb128(0)
    serializer.serialize_u8(0)
    serializer.serialize_u32_as_uleb128(1)
    serialize_account_address(serializer, node)
    serializer.serialize_u8(1)
    serializer.serialize_str("https://node.example/")
    enc_key.serialize(serializer)
    serializer.serialize_u32_as_uleb128(0)
    body = "0x" + serializer.to_bytes().hex()
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return body.encode("utf-8")

    def fake_urlopen(url):
        calls.append(url)
        return Response()

    monkeypatch.setattr(discovery, "urlopen", fake_urlopen)
    reader = discovery.DiscoveryChainReader("https://discovery.example/")

    assert reader.network_state().epoch == 0
    assert reader.worker_endpoint("0xa") == "https://node.example/"
    assert reader.worker_enc_key("0xa").to_hex() == enc_key.to_hex()
    assert calls == ["https://discovery.example/bcs"]


def test_admin_recovery_wire_formats_match_ts_rust_known_answer() -> None:
    eph_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    payload = admin_recovery.ReconstructionRequestPayload(
        chain_id=4,
        ace_addr=AccountAddress.from_str("0x" + "09" * 32),
        keypair_id=AccountAddress.from_str("0x" + "ab" * 32),
        epoch=5,
        eph_pke_ek=eph_ek,
    )

    expected = (
        "04"
        + "09" * 32
        + "ab" * 32
        + "0500000000000000"
        + "0120"
        + "07" * 32
    )
    assert payload.to_bytes().hex() == expected

    signing_key = sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32)))
    request = admin_recovery.ReconstructionRequest(payload, signing_key.sign(payload.to_bytes()))
    worker_bytes = admin_recovery.WorkerRequest.new_reconstruction(request).to_bytes()
    assert worker_bytes[0] == admin_recovery.WorkerRequest.SCHEME_RECONSTRUCTION == 3
    assert signing_key.public_key().verify(payload.to_bytes(), request.signature)

    response_serializer = Serializer()
    response_serializer.serialize_u64(3)
    response_serializer.serialize_u8(group.SCHEME_BLS12381G2)
    response_serializer.serialize_fixed_bytes((123456789).to_bytes(32, "little"))
    response = admin_recovery.parse_reconstruction_response(response_serializer.to_bytes())
    assert response.eval_point == 3
    assert response.group_scheme == group.SCHEME_BLS12381G2
    assert int.from_bytes(response.scalar, "little") == 123456789
    try:
        admin_recovery.parse_reconstruction_response(response_serializer.to_bytes() + b"\x00")
    except ValueError as err:
        assert "trailing bytes" in str(err)
    else:
        raise AssertionError("expected trailing bytes rejection")


def test_decryption_request_wire_formats_and_webauthn_challenge() -> None:
    eph_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    module_addr = AccountAddress.from_str("0x" + "09" * 32)
    contract_id = ContractID.new_aptos(4, module_addr, "m")
    payload = decryption.DecryptionRequestPayload(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        domain=b"label",
        ephemeral_enc_key=eph_ek,
    )

    expected = (
        "ab" * 32
        + "0500000000000000"
        + "00"
        + "04"
        + "09" * 32
        + "016d"
        + "056c6162656c"
        + "0120"
        + "07" * 32
    )
    assert payload.to_bytes().hex() == expected
    assert payload.to_webauthn_challenge().hex() == (
        "8b3d52f10fdbaf0aa78f966edf8ae21db10939bf7aca2c815626b825548006fa"
    )
    assert decryption.DecryptionRequestPayload.from_hex("0x" + expected).unwrap_or_throw(
        "payload"
    ).to_bytes() == payload.to_bytes()

    proof = decryption.ProofOfPermission.create_aptos_raw(b"\xaa\xbb")
    worker = decryption.WorkerRequest.new_decryption_basic_flow(
        payload, proof, t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).to_bytes()
    assert worker[0] == decryption.SCHEME_DECRYPTION_BASIC_FLOW
    assert worker.endswith(b"\x00\xaa\xbb\x01")

    custom = decryption.CustomFlowRequest(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        label=b"label",
        enc_pk=eph_ek,
        proof=decryption.CustomFlowProof.create_aptos(b"zk"),
    )
    custom_worker = decryption.WorkerRequest.new_decryption_custom_flow(
        custom, t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).to_bytes()
    assert custom_worker[0] == decryption.SCHEME_DECRYPTION_CUSTOM_FLOW
    assert custom_worker.endswith(b"\x00\x02zk\x01")


def test_decryption_core_fetches_verified_share_and_decrypts(monkeypatch) -> None:
    node = AccountAddress.from_str("0x1")
    keypair_id = AccountAddress.from_str("0x" + "cd" * 32)
    contract_id = ContractID.new_aptos(42, AccountAddress.from_str("0x1"), "example")
    fdd = FullDecryptionDomain(keypair_id, contract_id, b"object-id")
    plaintext = b"worker share decrypts"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    ciphertext = t_ibe.encrypt(mpk, fdd.to_bytes(), plaintext).unwrap_or_throw("encrypt")
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=fdd.to_bytes()).unwrap_or_throw("idk")
    eph_ek, eph_dk = pke.keygen()
    node_ek, node_dk = pke.keygen()
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    state = network.State(
        epoch=9,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
                expected_usage=network.USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
                note="ibe",
            )
        ],
        proposals=[],
        epoch_change_info=None,
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )

    class FakeReader:
        def network_state(self):
            return state

        def session(self, addr: str, is_dkg: bool = True):
            assert addr == "0x" + keypair_id.address.hex()
            assert is_dkg is True
            return session

        def worker_endpoint(self, addr: str) -> str:
            assert addr == "0x" + node.address.hex()
            return "https://node.example/"

        def worker_enc_key(self, addr: str):
            assert addr == "0x" + node.address.hex()
            return node_ek

    seen_request_plaintexts = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return pke.encrypt(eph_ek, idk.to_bytes()).to_hex().encode("utf-8")

    def fake_urlopen(request, timeout):
        del timeout
        request_ct = pke.Ciphertext.from_hex(request.data.decode("utf-8")).unwrap_or_throw("ct")
        request_plain = pke.decrypt(node_dk, request_ct).unwrap_or_throw("plain")
        seen_request_plaintexts.append(request_plain)
        return Response()

    monkeypatch.setattr(decryption, "get_chain_reader", lambda _deployment: FakeReader())
    monkeypatch.setattr(decryption, "urlopen", fake_urlopen)
    monkeypatch.setattr(ibe_aptos, "get_chain_reader", lambda _deployment: FakeReader())

    request = decryption.DecryptionRequestPayload(
        keypair_id=fdd.keypair_id,
        epoch=state.epoch,
        contract_id=fdd.contract_id,
        domain=fdd.label,
        ephemeral_enc_key=eph_ek,
    )
    proof = decryption.ProofOfPermission.create_aptos_raw(b"proof")
    result = decryption.decrypt_core(
        ace_deployment=ace_deployment,
        network_state=state,
        request=request,
        proof=proof,
        ephemeral_decryption_key=eph_dk,
        ciphertext=ciphertext.to_bytes(),
    )

    assert result.unwrap_or_throw("decrypt") == plaintext
    assert seen_request_plaintexts[0][0] == decryption.SCHEME_DECRYPTION_BASIC_FLOW

    per_node = decryption.build_per_node_request_core(
        ace_deployment=ace_deployment,
        network_state=state,
        request=request,
        proof=proof,
        tibe_scheme=t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        target_endpoint="https://node.example/",
    ).unwrap_or_throw("per-node")
    assert per_node.epoch == state.epoch
    assert per_node.sdk_idx == 0

    custom_result = ibe_aptos.decrypt_custom_flow(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        chain_id=42,
        module_addr=AccountAddress.from_str("0x1"),
        module_name="example",
        label=b"object-id",
        enc_pk=eph_ek.to_bytes(),
        enc_sk=eph_dk.to_bytes(),
        payload=b"custom-proof",
        ciphertext=ciphertext.to_bytes(),
    )

    assert custom_result.unwrap_or_throw("custom decrypt") == plaintext
    assert seen_request_plaintexts[-1][0] == decryption.SCHEME_DECRYPTION_CUSTOM_FLOW


def test_vrf_aptos_payload_share_verify_and_reconstruct() -> None:
    response_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    account = AccountAddress.from_str("0x" + "cd" * 32)
    contract_id = ContractID.new_aptos(
        4, AccountAddress.from_str("0x" + "ef" * 32), "presigned_access"
    )
    payload = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        label=b"label-1",
        account_address=account,
        response_enc_key=response_ek,
    )
    restored = vrf_aptos.ThresholdVrfRequestPayload.from_hex("0x" + payload.to_hex())

    assert restored.to_bytes() == payload.to_bytes()
    assert payload.to_webauthn_challenge().hex() == (
        "9808d30bb5e86a74b8a4823055747f23ca88e5b2a3d21648e663c41d6a019f1c"
    )
    assert payload.to_vrf_input_bytes().startswith(bytes([len("ace.threshold-vrf.input.v1")]))

    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    input_point = bls12381g1.PublicPoint(
        hash_to_G1(payload.to_vrf_input_bytes(), vrf_aptos.DST_THRESHOLD_VRF_G1, hashlib.sha256)
    )
    scalar = bls12381g1.PrivateScalar.from_bigint(msk.inner.scalar).unwrap_or_throw("scalar")
    share = vrf_aptos.ThresholdVrfShare(
        eval_point=1,
        share=group.Element.from_bls12381_g1(input_point.scale(scalar)),
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )

    assert vrf_aptos.ThresholdVrfShare.from_bytes(share.to_bytes()).to_bytes() == share.to_bytes()
    assert vrf_aptos.verify_threshold_vrf_share(
        share, 0, session, payload.to_vrf_input_bytes()
    )
    expected = hashlib.sha3_256(
        hashlib.sha3_256(b"ACE::ThresholdVrfOutput").digest() + share.share.inner.raw_bytes()
    ).digest()
    assert vrf_aptos.reconstruct_threshold_vrf([share]) == expected


def test_vrf_aptos_derive_core_with_fake_worker(monkeypatch) -> None:
    node = AccountAddress.from_str("0x1")
    account = AccountAddress.from_str("0x2")
    keypair_id = AccountAddress.from_str("0x" + "11" * 32)
    contract_id = ContractID.new_aptos(42, AccountAddress.from_str("0x1"), "example")
    response_ek, response_dk = pke.keygen()
    node_ek, node_dk = pke.keygen()
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    payload = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=keypair_id,
        epoch=8,
        contract_id=contract_id,
        label=b"vrf-label",
        account_address=account,
        response_enc_key=response_ek,
    )
    auth_proof = vrf_aptos.AptosProofOfPermission.new_ed25519(
        user_addr=account,
        public_key_bytes=bytes(32),
        signature_bytes=bytes(64),
        full_message="0x" + payload.to_hex(),
    )
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    state = network.State(
        epoch=8,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BLS12381_THRESHOLD_VRF,
                expected_usage=network.USAGE_BLS12381_THRESHOLD_VRF,
                note="vrf",
            )
        ],
        proposals=[],
        epoch_change_info=None,
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )
    input_point = bls12381g1.PublicPoint(
        hash_to_G1(payload.to_vrf_input_bytes(), vrf_aptos.DST_THRESHOLD_VRF_G1, hashlib.sha256)
    )
    scalar = bls12381g1.PrivateScalar.from_bigint(msk.inner.scalar).unwrap_or_throw("scalar")
    share = vrf_aptos.ThresholdVrfShare(
        eval_point=1,
        share=group.Element.from_bls12381_g1(input_point.scale(scalar)),
    )

    class FakeReader:
        def session(self, addr: str, is_dkg: bool = True):
            assert addr == "0x" + keypair_id.address.hex()
            assert is_dkg is True
            return session

        def worker_endpoint(self, addr: str) -> str:
            assert addr == "0x" + node.address.hex()
            return "https://node.example/"

        def worker_enc_key(self, addr: str):
            assert addr == "0x" + node.address.hex()
            return node_ek

    seen_request = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return pke.encrypt(response_ek, share.to_bytes()).to_hex().encode("utf-8")

    def fake_urlopen(request, timeout):
        del timeout
        request_ct = pke.Ciphertext.from_hex(request.data.decode("utf-8")).unwrap_or_throw("ct")
        plain = pke.decrypt(node_dk, request_ct).unwrap_or_throw("plain")
        seen_request.append(plain)
        return Response()

    monkeypatch.setattr(vrf_aptos, "get_chain_reader", lambda _deployment: FakeReader())
    monkeypatch.setattr(decryption, "get_chain_reader", lambda _deployment: FakeReader())
    monkeypatch.setattr(vrf_aptos, "urlopen", fake_urlopen)

    output = vrf_aptos.derive_core(
        ace_deployment=ace_deployment,
        network_state=state,
        payload=payload,
        auth_proof=auth_proof,
        response_decryption_key=response_dk,
    )

    assert len(output) == 32
    assert seen_request[0][0] == vrf_aptos.SCHEME_THRESHOLD_VRF


def test_admin_recovery_reconstruct_secret_with_fake_workers(monkeypatch) -> None:
    nodes = [AccountAddress.from_str("0x1"), AccountAddress.from_str("0x2")]
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    node_enc_key, node_dec_key = pke.keygen()
    eph_ek, eph_dk = pke.keygen()

    class FakeReader:
        def network_state(self):
            return network.State(
                epoch=7,
                epoch_start_time_micros=0,
                epoch_duration_micros=0,
                cur_nodes=nodes,
                cur_threshold=2,
                secrets=[],
                proposals=[],
                epoch_change_info=None,
            )

        def worker_endpoint(self, addr: str) -> str:
            return f"https://node-{addr[-1]}.example/"

        def worker_enc_key(self, addr: str):
            del addr
            return node_enc_key

    requests_seen = []

    def encrypted_response(eval_point: int, scalar: int) -> str:
        serializer = Serializer()
        serializer.serialize_u64(eval_point)
        serializer.serialize_u8(group.SCHEME_BLS12381G2)
        serializer.serialize_fixed_bytes(scalar.to_bytes(32, "little"))
        return pke.encrypt(eph_ek, serializer.to_bytes()).to_hex()

    class Response:
        status = 200

        def __init__(self, body: str) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return self._body.encode("utf-8")

    def fake_urlopen(request, timeout):
        del timeout
        requests_seen.append(request)
        body = request.data.decode("utf-8")
        ciphertext = pke.Ciphertext.from_hex(body).unwrap_or_throw("request ct")
        plain = pke.decrypt(node_dec_key, ciphertext).unwrap_or_throw("request plain")
        assert plain[0] == admin_recovery.SCHEME_RECONSTRUCTION
        if request.full_url == "https://node-1.example/":
            return Response(encrypted_response(1, 47))
        return Response(encrypted_response(2, 52))

    monkeypatch.setattr(admin_recovery, "get_chain_reader", lambda _deployment: FakeReader())
    monkeypatch.setattr(admin_recovery.pke, "keygen", lambda: (eph_ek, eph_dk))
    monkeypatch.setattr(admin_recovery, "fetch_tibe_public_key", lambda **_kwargs: Result.Err("skip"))
    monkeypatch.setattr(admin_recovery, "urlopen", fake_urlopen)

    result = admin_recovery.reconstruct_secret(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        signing_key=sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32))),
        chain_id=4,
    )

    assert result.secret_hex == "0x" + (42).to_bytes(32, "little").hex()
    assert result.epoch == 7
    assert result.shares_used == 2
    assert result.verified is None
    assert len(requests_seen) == 2

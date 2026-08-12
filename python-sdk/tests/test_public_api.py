# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

from aptos_sdk.account_address import AccountAddress

from ace_sdk import (
    group,
    ibe_aptos,
    known_deployments,
    network,
    pke,
    t_ibe,
)
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal import discovery
from ace_sdk.bcs import Serializer, serialize_account_address
from ace_sdk.group import bls12381g2

from tests.helpers import BytesResponse

NETWORK_STATE_EPOCH = 7
NETWORK_STATE_START_MICROS = 100
NETWORK_STATE_DURATION_MICROS = 200


def serialize_network_state_with_one_ibe_secret(
    node: AccountAddress,
    secret_session: AccountAddress,
    keypair_id: AccountAddress,
) -> bytes:
    serializer = Serializer()
    serializer.serialize_u64(NETWORK_STATE_EPOCH)
    serializer.serialize_u64(NETWORK_STATE_START_MICROS)
    serializer.serialize_u64(NETWORK_STATE_DURATION_MICROS)
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
    return serializer.to_bytes()


def serialize_discovery_snapshot_with_session(
    keypair_id: AccountAddress,
    base: group.Element,
    result_pk: group.Element,
) -> str:
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
    return "0x" + serializer.to_bytes().hex()


def serialize_discovery_snapshot_with_worker(
    node: AccountAddress,
    enc_key: pke.EncryptionKey,
) -> str:
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
    return "0x" + serializer.to_bytes().hex()


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

    state = network.State.from_bytes(
        serialize_network_state_with_one_ibe_secret(node, secret_session, keypair_id)
    ).unwrap_or_throw("state")

    assert state.epoch == NETWORK_STATE_EPOCH
    assert state.cur_threshold == 1
    assert state.secrets[0].scheme_name().endswith("(default)")
    assert state.active_proposals() == []
    assert not state.is_epoch_changing()


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

    body = serialize_discovery_snapshot_with_session(keypair_id, base, result_pk)
    monkeypatch.setattr(discovery, "urlopen", lambda _url: BytesResponse(body.encode("utf-8")))
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
    body = serialize_discovery_snapshot_with_worker(node, enc_key)
    calls = []

    def fake_urlopen(url):
        calls.append(url)
        return BytesResponse(body.encode("utf-8"))

    monkeypatch.setattr(discovery, "urlopen", fake_urlopen)
    reader = discovery.DiscoveryChainReader("https://discovery.example/")

    assert reader.network_state().epoch == 0
    assert reader.worker_endpoint("0xa") == "https://node.example/"
    assert reader.worker_enc_key("0xa").to_hex() == enc_key.to_hex()
    assert calls == ["https://discovery.example/bcs"]
